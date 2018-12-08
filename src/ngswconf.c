/*
 * ngswconf: NETGEAR(R) Switch Configuration Downloader
 * Copyright (C) 2018  Niels Penneman
 *
 * This file is part of ngswconf.
 *
 * ngswconf is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * ngswconf is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with ngswconf. If not, see <https://www.gnu.org/licenses/>.
 *
 * NETGEAR and ProSAFE are registered trademarks of NETGEAR, Inc. and/or its
 * subsidiaries in the United States and/or other countries.
 */


#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <curl/curl.h>
#include <sys/types.h>


#define COOKIE_SID_PATH   "/"
#define COOKIE_SID_NAME   "SID"

#define ENV_VAR_PASSWORD  "NETGEAR_SWITCH_PASSWORD"

#define URL_CONFIG    "http://%s/filesystem/startup-config"
#define URL_LOGOUT    "http://%s/base/status.html"

#define LOGIN_FAILED  "<INPUT class=\"input\" type=\"PASSWORD\" name=\"pwd\""
#define LOGIN_FIELDS  "pwd=%s"


typedef struct
{
  const char *name;
  const char *loginURL;
  int logoutSetSessionId;
} Model;

size_t curl_store_data(char *ptr, size_t size, size_t nmemb, void *userdata);
size_t curl_swallow_data(char *ptr, size_t size, size_t nmemb, void *userdata);
const Model *get_model(const char *name);
int is_session_id_cookie(const char *cookie, const char **sessionID);
int request_config(const char *host, CURL *curl);
int request_login(const Model *model, const char *host, const char *password,
  CURL *curl);
void request_logout(const Model *model, const char *host, CURL *curl);
int write_config(FILE *file);

enum
{
  BUFFER_SIZE             = 1 << 15 /* 32 kB */,
  COOKIE_FIELDS           = 7,
  COOKIE_TABS             = COOKIE_FIELDS - 1,
  HTTP_STATUS_OK          = 200,
  HTTP_STATUS_NO_CONTENT  = 204,
  MAX_HOSTNAME_SIZE       = 32,
  MAX_PASSWORD_SIZE       = 64,
  PASSWORD_BUFFER_SIZE    = MAX_PASSWORD_SIZE + 5,
  SESSION_ID_BUFFER_SIZE  = 86,
  URL_BUFFER_SIZE         = 34 + MAX_HOSTNAME_SIZE
};

static const Model MODELS[] = {
  { "GS108Tv2", "http://%s/base/main_login.html",    1 },
  { "GS724Tv4", "http://%s/base/cheetah_login.html", 0 }
};

static char g_buffer[BUFFER_SIZE];
static size_t g_bufferPos = 0;


size_t curl_store_data(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void)size;
  (void)userdata;
  if ((g_bufferPos + nmemb) >= BUFFER_SIZE)
  {
    fputs("Write buffer overflow\n", stderr);
    return 0;
  }
  memcpy(g_buffer + g_bufferPos, ptr, nmemb);
  g_bufferPos += nmemb;
  return nmemb;
}

size_t curl_swallow_data(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void)ptr;
  (void)size;
  (void)userdata;
  return nmemb;
}

const Model *get_model(const char *name)
{
  for (size_t m = 0; m < (sizeof(MODELS) / sizeof(Model)); ++m)
  {
    if (strcmp(MODELS[m].name, name) == 0)
    {
      return &MODELS[m];
    }
  }
  return NULL;
}

int is_session_id_cookie(const char *cookie, const char **sessionID)
{
  // Cookie fields, tab-separated: DOMAIN FLAG PATH SECURE EXPIRATION NAME VALUE
  ptrdiff_t t[COOKIE_TABS];
  for (int i = 0; i < COOKIE_TABS; ++i)
  {
    const char *const tab = strchr(cookie + (i > 0 ? t[i - 1] + 1 : 0), '\t');
    if (!tab)
    {
      return 0;
    }
    t[i] = tab - cookie;
  }

  // Verify path
  if ((t[2] - t[1] - 1) != strlen(COOKIE_SID_PATH)
      || strncmp(cookie + t[1] + 1, COOKIE_SID_PATH, strlen(COOKIE_SID_PATH)))
  {
    return 0;
  }

  // Verify name
  if ((t[5] - t[4] - 1) != strlen(COOKIE_SID_NAME)
      || strncmp(cookie + t[4] + 1, COOKIE_SID_NAME, strlen(COOKIE_SID_NAME)))
  {
    return 0;
  }

  *sessionID = cookie + t[COOKIE_TABS - 1] + 1;
  return 1;
}

int main(int argc, const char **argv)
{
  if (geteuid() == 0)
  {
    fputs("Should not be run as root", stderr);
    return 1;
  }

  if (argc < 3 || argc > 4)
  {
    fprintf(stderr, "Usage: %s SWITCH_MODEL HOST_OR_IP [OUTFILE]\n", argv[0]);
    return 1;
  }

  const Model *model = get_model(argv[1]);
  const char *host = argv[2];
  const char *outFileName = argc > 3 ? argv[3] : NULL;
  FILE *outFile = stdout;

  if (!model)
  {
    fprintf(stderr, "Unknown model: %s\n", argv[1]);
    return 1;
  }

  if (strlen(host) > MAX_HOSTNAME_SIZE)
  {
    fputs("Host/IP too long\n", stderr);
    return 1;
  }

  char *password = getenv(ENV_VAR_PASSWORD);
  if (!password)
  {
    fprintf(stderr, "Password must be set in the %s environment variable\n",
      ENV_VAR_PASSWORD);
    return 1;
  }
  if (strlen(password) > MAX_PASSWORD_SIZE)
  {
    fputs("Password too long\n", stderr);
    return 1;
  }

  curl_global_init(CURL_GLOBAL_NOTHING);

  CURL *curl = curl_easy_init();
  int ret = 0;
  if (curl)
  {
    /* Log in, get the configuration and then log out. The latter is important
     * as these switches limit the amount of 'open' HTTP sessions, and it can
     * take the switch several minutes to automatically close an inactive HTTP
     * session (depending on the configuration). */
    ret = request_login(model, host, password, curl);
    if (ret == 0)
    {
      ret = request_config(host, curl);
      request_logout(model, host, curl);
    }
    curl_easy_cleanup(curl);

    /* CURL could print the configuration if we don't configure a custom write
     * callback for the configuration request. This would however also print
     * errors. Therefore we first store the configuration in memory and only
     * when successful, we print the contents of our buffer to STDOUT. */
    if (!ret && outFileName)
    {
      outFile = fopen(outFileName, "wb");
      if (!outFile)
      {
        perror("Failed to open output file");
        ret = 1;
      }
    }
    ret = ret ? ret : write_config(outFile);
    if (outFileName && outFile)
    {
      fclose(outFile);
    }
  }
  else
  {
    fputs("Failed to initialize CURL\n", stderr);
    ret = 1;
  }

  curl_global_cleanup();
  return ret;
}

int request_config(const char *host, CURL *curl)
{
  char url[URL_BUFFER_SIZE];
  int r;
  CURLcode cr;
  long status = 0;

  r = snprintf(url, URL_BUFFER_SIZE, URL_CONFIG, host);
  if (r < 0 || r >= URL_BUFFER_SIZE)
  {
    fputs("Failed to retrieve configuration: error formatting URL\n", stderr);
    return 1;
  }

  curl_easy_reset(curl);
  cr = curl_easy_setopt(curl, CURLOPT_URL, url);
  cr = cr ? cr : curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_store_data);
  cr = cr ? cr : curl_easy_perform(curl);
  cr = cr ? cr : curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

  if (cr != CURLE_OK)
  {
    fprintf(stderr, "Failed to retrieve configuration: %s\n",
      curl_easy_strerror(cr));
    return 1;
  }

  if (status != HTTP_STATUS_OK)
  {
    fprintf(stderr,
      "Failed to retrieve configuration; HTTP response code: %ld\n", status);
    return 1;
  }

  return 0;
}

int request_login(const Model *model, const char *host, const char *password,
  CURL *curl)
{
  char data[PASSWORD_BUFFER_SIZE];
  char url[URL_BUFFER_SIZE];
  int r;
  CURLcode cr;
  long status = 0;

  r = snprintf(url, URL_BUFFER_SIZE, model->loginURL, host);
  if (r < 0 || r >= URL_BUFFER_SIZE)
  {
    fputs("Failed to log in: error formatting URL\n", stderr);
    return 1;
  }

  r = snprintf(data, PASSWORD_BUFFER_SIZE, LOGIN_FIELDS, password);
  if (r < 0 || r >= PASSWORD_BUFFER_SIZE)
  {
    fputs("Failed to log in: error formatting data\n", stderr);
    return 1;
  }

  curl_easy_reset(curl);
  cr = curl_easy_setopt(curl, CURLOPT_URL, url);
  cr = cr ? cr : curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
  cr = cr ? cr : curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
  cr = cr ? cr : curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_store_data);
  cr = cr ? cr : curl_easy_perform(curl);
  cr = cr ? cr : curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  if (cr != CURLE_OK)
  {
    fprintf(stderr, "Failed to log in: %s\n", curl_easy_strerror(cr));
    return 1;
  }
  if (status != HTTP_STATUS_OK)
  {
    fprintf(stderr, "Failed to log in; HTTP response code: %ld\n", status);
    return 1;
  }

  g_buffer[g_bufferPos] = 0;
  if (strstr(g_buffer, LOGIN_FAILED))
  {
    fprintf(stderr, "Failed to log in: rejected by device\n");
    return 1;
  }
  g_bufferPos = 0;
  return 0;
}

void request_logout(const Model *model, const char *host, CURL *curl)
{
  char url[URL_BUFFER_SIZE];
  char dataBuffer[SESSION_ID_BUFFER_SIZE];
  const char *data;
  int r;
  CURLcode cr;
  long status = 0;

  r = snprintf(url, URL_BUFFER_SIZE, URL_LOGOUT, host);
  if (r < 0 || r >= URL_BUFFER_SIZE)
  {
    fputs("Failed to log out: error formatting URL\n", stderr);
    return;
  }

  if (model->logoutSetSessionId)
  {
    struct curl_slist *cookies;
    cr = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
    if (cr != CURLE_OK)
    {
      fprintf(stderr, "Failed to log out: %s\n", curl_easy_strerror(cr));
      return;
    }
    if (!cookies)
    {
      fputs("Failed to log out: cannot retrieve session cookie\n", stderr);
      return;
    }
    const struct curl_slist *cookie = cookies;
    int cookieFound = 0;
    while (cookie)
    {
      const char *sessionID = NULL;
      if (is_session_id_cookie(cookie->data, &sessionID))
      {
        cookieFound = 1;
        r = snprintf(dataBuffer, SESSION_ID_BUFFER_SIZE, "sessionID=%s",
          sessionID);
        break;
      }
      cookie = cookie->next;
    }
    curl_slist_free_all(cookies);
    if (!cookieFound)
    {
      fputs("Failed to log out: session ID cookie not found\n", stderr);
      return;
    }
    if (r < 0 || r >= SESSION_ID_BUFFER_SIZE)
    {
      fputs("Failed to log out: error formatting data\n", stderr);
      return;
    }
    data = dataBuffer;
  }
  else
  {
    data = "sessionID=";
  }

  curl_easy_reset(curl);
  cr = curl_easy_setopt(curl, CURLOPT_URL, url);
  cr = cr ? cr : curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
  cr = cr ? cr : curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
    curl_swallow_data);
  cr = cr ? cr : curl_easy_perform(curl);
  cr = cr ? cr : curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  if (cr != CURLE_OK)
  {
    fprintf(stderr, "Failed to log out: %s\n", curl_easy_strerror(cr));
  }
  else if (status != HTTP_STATUS_NO_CONTENT)
  {
    fprintf(stderr, "Failed to log out; HTTP response code: %ld\n", status);
  }
}

int write_config(FILE *file)
{
  if (g_bufferPos > 0)
  {
    size_t written = fwrite(g_buffer, 1, g_bufferPos, file);
    if (written != g_bufferPos)
    {
      fputs("Failed to write configuration\n", stderr);
      return 1;
    }
  }
  return 0;
}

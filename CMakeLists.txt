#  ngswconf: NETGEAR(R) Switch Configuration Downloader
#  Copyright (C) 2018  Niels Penneman
#
#  This file is part of ngswconf.
#
#  ngswconf is free software: you can redistribute it and/or modify it under the
#  terms of the GNU Affero General Public License as published by the Free
#  Software Foundation, either version 3 of the License, or (at your option) any
#  later version.
#
#  ngswconf is distributed in the hope that it will be useful, but WITHOUT ANY
#  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
#  A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
#  details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with ngswconf. If not, see <https://www.gnu.org/licenses/>.
#
#  NETGEAR and ProSAFE are registered trademarks of NETGEAR, Inc. and/or its
#  subsidiaries in the United States and/or other countries.


cmake_minimum_required(VERSION 3.7.2 FATAL_ERROR)

project(ngswconf)

find_package(CURL REQUIRED)

add_compile_options(-Wall -Wextra -std=c99 -Os -DNDEBUG)
include_directories(${CURL_INCLUDE_DIR})

add_executable(ngswconf src/ngswconf.c)
target_link_libraries(ngswconf ${CURL_LIBRARIES})

install(TARGETS ngswconf DESTINATION bin)

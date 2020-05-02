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


cmake_minimum_required (VERSION 3.7.2 FATAL_ERROR)

project (ngswconf C)


set (SRC_DIR "${PROJECT_SOURCE_DIR}/src")

find_package (CURL REQUIRED)

include_directories (
  ${CURL_INCLUDE_DIR}
)

set (default_build_type "Release")
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message (STATUS "Build type set to default '${default_build_type}'")
  set (CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
  set_property (CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")
endif()

set (CMAKE_C_FLAGS "-std=c99")
set (CMAKE_C_FLAGS_DEBUG "-ggdb3 -fsanitize=address,undefined")
set (CMAKE_C_FLAGS_RELEASE "-DNDEBUG -Os")

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
  set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -flto -ffunction-sections -fdata-sections")
  set (CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wl,--gc-sections")
endif ()


add_executable (ngswconf src/ngswconf.c)
target_link_libraries (ngswconf
  ${CURL_LIBRARIES}
)


install (TARGETS ngswconf DESTINATION bin)


set (CPACK_GENERATOR "DEB")
set (CPACK_DEBIAN_PACKAGE_DEPENDS "libcurl4(>=7.64.0)")
set (CPACK_DEBIAN_PACKAGE_MAINTAINER "Niels Penneman")
set (CPACK_PACKAGE_VERSION_MAJOR 0)
set (CPACK_PACKAGE_VERSION_MINOR 9)
set (CPACK_PACKAGE_VERSION_PATCH 0)
set (CPACK_DEBIAN_PACKAGE_RELEASE 1)

include (CPack)

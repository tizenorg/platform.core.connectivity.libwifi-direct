CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(libwifi-direct C)

#SET(PREFIX $(CMAKE_INSTALL_PREFIX))
SET(prefix "/usr")
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")

ADD_SUBDIRECTORY(src)

IF("${ARCH}" MATCHES "arm")
	ADD_SUBDIRECTORY(binary)
ENDIF()

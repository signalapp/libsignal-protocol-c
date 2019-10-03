cmake_minimum_required(VERSION 3.4)
project(signal-protocol-c
  VERSION 2.3.2
  LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/CMakeModules")

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckCCompilerFlag)
include(CheckSymbolExists)
include(GNUInstallDirs)
include(TestBigEndian)
include(CTest)

include(SignalCheck)

signal_check_lint(missing-field-initializers)
signal_check_lint(sign-conversion)
signal_check_lint(sign-compare)
signal_check_lint(parentheses)
signal_check_lint(all)

signal_check_lint(shorten-64-to-32)
signal_check_lint(unused-variable)
signal_check_lint(int-conversion)
signal_check_lint(unused-value)
signal_check_lint(pointer-sign)
signal_check_lint(protocol)
signal_check_lint(shadow)
signal_check_lint(switch)

signal_check_lint(missing-braces)

check_c_compiler_flag(-fmessage-length=0 SIGNAL_CODEGEN_MESSAGE_LENGTH)

check_symbol_exists(memset_s "string.h" SIGNAL_HAVE_MEMset_S)
check_symbol_exists(SecureZeroMemory
  "Windows.h;WinBase.h"
  SIGNAL_HAVE_SECUREZEROMEMORY)

test_big_endian(SIGNAL_BIG_ENDIAN)

# Setting generator expressions like this make them a bit easier to read
set(codegen-message-length
  $<$<BOOL:${SIGNAL_CODEGEN_MESSAGE_LENGTH}>:-fmessage-length=0>)

add_compile_options(
  ${codegen-message-length}

  ${lint-allow-missing-braces}

  ${lint-deny-missing-field-initializers}
  ${lint-deny-sign-conversion}
  ${lint-deny-sign-compare}
  ${lint-deny-parentheses}
  ${lint-deny-default}

  ${lint-deny-shorten-64-to-32}
  ${lint-deny-unused-variable}
  ${lint-deny-int-conversion}
  ${lint-deny-unused-value}
  ${lint-deny-pointer-sign}
  ${lint-deny-protocol}
  ${lint-deny-shadow}
  ${lint-deny-switch})

add_compile_definitions(
  HAVE_MEMset_S=$<BOOL:${SIGNAL_HAVE_MEMset_S}>
  $<$<BOOL:${SIGNAL_BIG_ENDIAN}>:WORDS_BIGENDIAN>)

configure_file(src/libsignal-protocol-c.pc.in libsignal-protocol-c.pc @ONLY)
configure_package_config_file(
  ${PROJECT_SOURCE_DIR}/CMakeModules/signal-protocol-config.cmake.in
  ${PROJECT_BINARY_DIR}/signal-protocol-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_DATADIR}/cmake/signal-protocol
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
  NO_SET_AND_CHECK_MACRO)

write_basic_package_version_file(signal-protocol-config-version.cmake
  COMPATIBILITY SameMajorVersion)

add_subdirectory(src)

install(TARGETS signal-protocol-c EXPORT signal-protocol-targets
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/signal"
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(EXPORT signal-protocol-targets
  NAMESPACE signal::
  DESTINATION ${CMAKE_INSTALL_DATADIR}/cmake/signal-protocol)

install(FILES ${PROJECT_BINARY_DIR}/libsignal-protocol-c.pc
  DESTINATION ${CMAKE_INSTALL_DATADIR}/pkgconfig)

install(FILES
  "${PROJECT_BINARY_DIR}/signal-protocol-config-version.cmake"
  "${PROJECT_BINARY_DIR}/signal-protocol-config.cmake"
  DESTINATION ${CMAKE_INSTALL_DATADIR}/cmake/signal-protocol)

if(COVERAGE)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
	set(LINK_FLAGS "${LINK_FLAGS} -fprofile-arcs -ftest-coverage")

	add_custom_command(OUTPUT run_coverage
			COMMAND ctest
			COMMAND lcov -q --capture --directory src --output-file coverage.info.total
			COMMAND lcov -q --remove coverage.info.total 'vpool.*' 'ut*.h' '*.pb-c.*' 'protobuf-c/*' 'curve25519/*' --output-file coverage.info
			COMMAND genhtml -q coverage.info --output-directory coverage
			COMMENT Collecting and creating coverage information
	)
	add_custom_target( coverage DEPENDS run_coverage )
endif()

if(BUILD_TESTING)
	add_subdirectory(tests)
endif()

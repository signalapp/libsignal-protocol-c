enable_testing()
find_library(M_LIB m)
find_package(Check REQUIRED)
find_package(OpenSSL 1.0 REQUIRED)
find_package(Threads)
include_directories(${CHECK_INCLUDE_DIRS})

IF(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function")
ENDIF(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")

IF(CMAKE_COMPILER_IS_GNUCC)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-sign-compare -Wno-sign-conversion")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

IF(CMAKE_C_COMPILER_ID MATCHES "Clang")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-invalid-source-encoding -Wno-shorten-64-to-32")
ENDIF(CMAKE_C_COMPILER_ID MATCHES "Clang")

set(LIBS ${LIBS}
	${M_LIB}
	${CHECK_LIBRARIES}
	${OPENSSL_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	axolotl-c
)

set(common_SRCS
	test_common.c
	test_common.h
)

include_directories(. ../src ${OPENSSL_INCLUDE_DIR})

add_executable(test_curve25519 test_curve25519.c ${common_SRCS})
target_link_libraries(test_curve25519 ${LIBS})
add_test(test_curve25519 ${CMAKE_CURRENT_BINARY_DIR}/test_curve25519)

add_executable(test_hkdf test_hkdf.c ${common_SRCS})
target_link_libraries(test_hkdf ${LIBS})
add_test(test_hkdf ${CMAKE_CURRENT_BINARY_DIR}/test_hkdf)

add_executable(test_ratchet test_ratchet.c ${common_SRCS})
target_link_libraries(test_ratchet ${LIBS})
add_test(test_ratchet ${CMAKE_CURRENT_BINARY_DIR}/test_ratchet)

add_executable(test_protocol test_protocol.c ${common_SRCS})
target_link_libraries(test_protocol ${LIBS})
add_test(test_protocol ${CMAKE_CURRENT_BINARY_DIR}/test_protocol)

add_executable(test_session_record test_session_record.c ${common_SRCS})
target_link_libraries(test_session_record ${LIBS})
add_test(test_session_record ${CMAKE_CURRENT_BINARY_DIR}/test_session_record)

add_executable(test_session_cipher test_session_cipher.c ${common_SRCS})
target_link_libraries(test_session_cipher ${LIBS})
add_test(test_session_cipher ${CMAKE_CURRENT_BINARY_DIR}/test_session_cipher)

add_executable(test_session_builder test_session_builder.c ${common_SRCS})
target_link_libraries(test_session_builder ${LIBS})
add_test(test_session_builder ${CMAKE_CURRENT_BINARY_DIR}/test_session_builder)

add_executable(test_key_helper test_key_helper.c ${common_SRCS})
target_link_libraries(test_key_helper ${LIBS})
add_test(test_key_helper ${CMAKE_CURRENT_BINARY_DIR}/test_key_helper)

add_executable(test_simultaneous_initiate test_simultaneous_initiate.c ${common_SRCS})
target_link_libraries(test_simultaneous_initiate ${LIBS})
add_test(test_simultaneous_initiate ${CMAKE_CURRENT_BINARY_DIR}/test_simultaneous_initiate)

add_executable(test_sender_key_record test_sender_key_record.c ${common_SRCS})
target_link_libraries(test_sender_key_record ${LIBS})
add_test(test_sender_key_record ${CMAKE_CURRENT_BINARY_DIR}/test_sender_key_record)

add_executable(test_group_cipher test_group_cipher.c ${common_SRCS})
target_link_libraries(test_group_cipher ${LIBS})
add_test(test_group_cipher ${CMAKE_CURRENT_BINARY_DIR}/test_group_cipher)

add_executable(test_fingerprint test_fingerprint.c ${common_SRCS})
target_link_libraries(test_fingerprint ${LIBS})
add_test(test_fingerprint ${CMAKE_CURRENT_BINARY_DIR}/test_fingerprint)

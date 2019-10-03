find_library(M_LIB m)

add_library(signal-protocol-c)
add_library(signal::protocol ALIAS signal-protocol-c)

add_subdirectory(curve25519)
add_subdirectory(protobuf-c)

target_sources(signal-protocol-c
  PRIVATE
    LocalStorageProtocol.pb-c.c
    WhisperTextProtocol.pb-c.c
    FingerprintProtocol.pb-c.c)
target_sources(signal-protocol-c
  PRIVATE
	  vpool.c
	  signal_protocol.c
	  signal_protocol_types.h
	  curve.c
	  hkdf.c
	  ratchet.c
	  protocol.c
	  session_state.c
	  session_record.c
	  session_pre_key.c
	  session_builder.c
	  session_cipher.c
	  key_helper.c
	  sender_key.c
	  sender_key_state.c
	  sender_key_record.c
	  group_session_builder.c
	  group_cipher.c
	  fingerprint.c
	  device_consistency.c)

target_sources(signal-protocol-c PRIVATE
	$<TARGET_OBJECTS:curve25519>
	$<TARGET_OBJECTS:protobuf-c>)

target_include_directories(signal-protocol-c
  PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/curve25519/ed25519/nacl_includes>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/curve25519/ed25519/additions>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/curve25519/ed25519/sha512>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/curve25519/ed25519>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/curve25519>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(signal-protocol-c
  PRIVATE
    $<$<BOOL:${M_LIB}>:${M_LIB}>)

set_target_properties(signal-protocol-c
  PROPERTIES
    EXPORT_NAME protocol
    SOVERSION "${PROJECT_VERSION_MAJOR}"
    VERSION "${PROJECT_VERSION}")

# Signal is one of the few libraries that actually doesn't required a
# directory hierarchy for its headers, so we can just use the PUBLIC_HEADER
# property
set_property(TARGET signal-protocol-c APPEND
  PROPERTY
    PUBLIC_HEADER
	    src/signal_protocol.h
	    src/signal_protocol_types.h
	    src/curve.h
	    src/hkdf.h
	    src/ratchet.h
	    src/protocol.h
	    src/session_state.h
	    src/session_record.h
	    src/session_pre_key.h
	    src/session_builder.h
	    src/session_cipher.h
	    src/key_helper.h
	    src/sender_key.h
	    src/sender_key_state.h
	    src/sender_key_record.h
	    src/group_session_builder.h
	    src/group_cipher.h
	    src/fingerprint.h
	    src/device_consistency.h)

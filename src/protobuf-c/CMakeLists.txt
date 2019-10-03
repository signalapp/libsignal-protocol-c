
add_library(protobuf-c OBJECT)
target_sources(protobuf-c PRIVATE protobuf-c.c)
target_compile_options(protobuf-c
  PRIVATE
    ${lint-allow-shorten-64-to-32}
    ${lint-allow-sign-conversion}
    ${lint-allow-sign-compare}
    ${lint-allow-shadow})
set_property(TARGET protobuf-c
  PROPERTY
    POSITION_INDEPENDENT_CODE ${BUILD_SHARED_LIBS})

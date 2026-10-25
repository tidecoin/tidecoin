# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include_guard(GLOBAL)
include(CheckCSourceCompiles)

# Probe C compile options independently of the C++ compiler. Link options are
# handled separately: Tidecoin's executables link the C libraries through C++.
# TARGET, VAR, SOURCE, RESULT_VAR and IF_CHECK_PASSED have the same meaning as
# in try_append_cxx_flags. Options on TARGET apply only to C translation units.
function(try_append_c_flags flags)
  cmake_parse_arguments(PARSE_ARGV 1
    TACF
    ""
    "TARGET;VAR;SOURCE;RESULT_VAR"
    "IF_CHECK_PASSED"
  )

  string(MAKE_C_IDENTIFIER "${flags}" id_string)
  string(TOUPPER "${id_string}" id_string)
  set(source "int main(void) { return 0; }")
  if(DEFINED TACF_SOURCE AND NOT TACF_SOURCE STREQUAL source)
    set(source "${TACF_SOURCE}")
    string(SHA256 source_hash "${source}")
    string(SUBSTRING ${source_hash} 0 4 source_hash_head)
    string(APPEND id_string _${source_hash_head})
  endif()

  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
  set(CMAKE_REQUIRED_FLAGS "${flags} ${working_c_compiler_werror_flag}")
  set(compiler_result C_SUPPORTS_${id_string})
  check_c_source_compiles("${source}" ${compiler_result})

  if(${compiler_result})
    if(DEFINED TACF_IF_CHECK_PASSED)
      set(options ${TACF_IF_CHECK_PASSED})
    else()
      separate_arguments(options NATIVE_COMMAND "${flags}")
    endif()
    if(DEFINED TACF_TARGET)
      foreach(option IN LISTS options)
        target_compile_options(${TACF_TARGET} INTERFACE "$<$<COMPILE_LANGUAGE:C>:${option}>")
      endforeach()
    endif()
    if(DEFINED TACF_VAR)
      list(JOIN options " " options_string)
      string(STRIP "${${TACF_VAR}} ${options_string}" ${TACF_VAR})
    endif()
  endif()

  if(DEFINED TACF_VAR)
    set(${TACF_VAR} "${${TACF_VAR}}" PARENT_SCOPE)
  endif()
  if(DEFINED TACF_RESULT_VAR)
    set(${TACF_RESULT_VAR} "${${compiler_result}}" PARENT_SCOPE)
  endif()
endfunction()

if(MSVC)
  try_append_c_flags("/WX /options:strict" VAR working_c_compiler_werror_flag)
else()
  try_append_c_flags("-Werror" VAR working_c_compiler_werror_flag)
endif()

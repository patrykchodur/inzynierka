
set(PLUGIN_NAME gemroc_dissector)
include(WiresharkPlugin)

set_module_info(${PLUGIN_NAME} 0 0 1 0)

set(DISSECTOR_SRC
	main.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_plugin_library(${PLUGIN_NAME} epan)

target_link_libraries(${PLUGIN_NAME} epan)

install_plugin(${PLUGIN_NAME} epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  ${PLUGIN_NAME}
	SWITCHES
	  -g abort -g termoutput
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)


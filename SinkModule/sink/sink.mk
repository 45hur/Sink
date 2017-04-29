sink_CFLAGS := -fvisibility=hidden -fPIC
sink_SOURCES := modules/sink/sink.c
sink_DEPEND := $(libkres)
sink_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS) 
$(call make_c_module,sink)

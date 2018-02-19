whalebone_CFLAGS := -fvisibility=hidden -fPIC
whalebone_SOURCES := modules/whalebone/whalebone.c
whalebone_DEPEND := $(libkres)
whalebone_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS) 
$(call make_c_module,whalebone)

LOCAL_PATH			:= $(call my-dir)

############### mainso ##################
include $(CLEAR_VARS)

LOCAL_MODULE		:= hijacker
LOCAL_ARM_MODE		:= arm
LOCAL_CPP_EXTENSION	:= .cpp
LOCAL_C_INCLUDES	:= $(LOCAL_PATH)
LOCAL_LDLIBS		:= -llog -landroid
LOCAL_SRC_FILES		:=	main.cpp \
						Substrate/hde64.c \
                  		Substrate/SubstrateDebug.cpp \
                   		Substrate/SubstrateHook.cpp \
                   		Substrate/SubstratePosixMemory.cpp

include $(BUILD_EXECUTABLE)
############# install ##############
include $(CLEAR_VARS)

temp_path	:= /data/local/tmp

all:
	adb push $(NDK_APP_DST_DIR)/hijacker $(temp_path)
	adb shell "su -c 'chmod 777 $(temp_path)/*'"
package com.sama.app;

public class NativeMethod {
    static {
        System.loadLibrary("samaso");
    }
    public static native void startSamah(int port);
    public static native void stopSamah();
}

package com.sama.app;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.concurrent.TimeUnit;

import okhttp3.Authenticator;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.logging.HttpLoggingInterceptor;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

public class Api {
    private static final String TAG = "Api";
    public static final String BASE_URL = "http://127.0.0.1:55520/";
    private static volatile Api instance;
    private ApiService mApiService;

    public static Api getInstance() {
        if (instance == null) {
            instance = new Api();
        }
        return instance;
    }

    public Api() {
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd HH:mm:ss")
                .serializeNulls().create();
        Interceptor interceptor = chain -> chain.proceed(chain.request().newBuilder()
                .addHeader("access_token", "78daef46-96df-44f5-b59a-8e9cbb187f7d")
                .build());
        Authenticator authenticator = (route, response) -> {
            //LoginActivity.start(App.getApp());
            return null;
        };
        HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
        logging.setLevel(HttpLoggingInterceptor.Level.BODY);
        OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .addInterceptor(interceptor)
                .authenticator(authenticator)
                .addInterceptor(logging)
                .connectTimeout(1, TimeUnit.MINUTES)
                .readTimeout(1, TimeUnit.MINUTES)
                .writeTimeout(1, TimeUnit.MINUTES)
                .build();
        mApiService = new Retrofit.Builder()
                .client(okHttpClient)
                .baseUrl(Api.BASE_URL)
                .addConverterFactory(GsonConverterFactory.create(gson))
                .build()
                .create(ApiService.class);
    }

    public ApiService getApiService() {
        return mApiService;
    }
}

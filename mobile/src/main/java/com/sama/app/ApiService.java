package com.sama.app;


import com.google.gson.JsonObject;

import java.util.HashMap;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.POST;

public interface ApiService {
    @POST("/")
    Call<JsonObject> call(@Body HashMap<String, Object> body);
}



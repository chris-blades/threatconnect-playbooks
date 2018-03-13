package com.threatconnect.app.hash;

import com.threatconnect.app.apps.App;
import com.threatconnect.app.apps.AppConfig;
import com.threatconnect.sdk.app.AppMain;

public class GetHashesAppMain extends AppMain {
    @Override
    public Class<? extends App> getAppClassToExecute(final AppConfig appConfig) throws ClassNotFoundException
    {
        return GetHashesApp.class;
    }

    public static void main(String[] args)
    {
        new GetHashesAppMain().execute();
    }
}

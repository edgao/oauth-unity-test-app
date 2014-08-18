oauth-unity-test-app
====================
A Unity platform to test OAuth providers

BUILDING
========
To build to the first set of apps, just go to File->BuildSettings->PlayerSettings->Build (save it to "release oauthtest1.apk)"  
Bundle ID: com.mogotxt.oauth1  
Google Play Services App ID: 914214743891

To build to the second set of apps:  
Assets/Plugins/Android/AndroidManifest.xml - comment out the first Facebook App ID tag and uncomment the second  
Assets/OauthTestGUI.CS - comment out the first TwitterAndroid.init and uncomment the second  
Google Play Services App ID: 936462937010  
File->BuildSettings->PlayerSettings - Change the bundle ID from com.mogotxt.oauth1 to com.mogotxt.oauth2; change the name to OauthUnityTest2  
Save the file to "release oauthtest2.apk"

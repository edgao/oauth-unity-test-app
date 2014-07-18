oauth-unity-test-app
====================

A Unity platform to test OAuth providers

BUILDING
========
Assets/Plugins/Android/AndroidManifest.xml - comment out the first Facebook App ID tag and uncomment the second
Assets/OauthTestGUI.CS - comment out the first TwitterAndroid.init and uncomment the second
File->BuildSettings->PlayerSettings - Change the bundle ID from com.mogo.strikerfc to com.mogotxt.oauth2

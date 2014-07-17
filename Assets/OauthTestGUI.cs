using UnityEngine;
using System.Collections;
using System.Text;
using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Collections.Generic;

public class OauthTestGUI : MonoBehaviour {

    private Boolean isFB = true;
    string url = "";
    
	// Use this for initialization
	void Start () {
        FacebookAndroid.init();
        // This is technically a security issue - having the consumer secret in plaintext is bad practice.
        TwitterAndroid.init("F2FsdXIWjWTexgu55Cf6ER9Ld", "mh3VaoX2XpXvky0IUylDeSH742zUbtyMU61pOS2MBkPsivr5fd");
	}
	
	// Update is called once per frame
	void Update () {
	}

    void OnGUI()
    {
        GUIStyle labelStyle = new GUIStyle(GUI.skin.label);
        labelStyle.fontSize = 40;
        GUIStyle buttonStyle = new GUIStyle(GUI.skin.button);
        buttonStyle.fontSize = 40;
        GUIStyle textFieldStyle = new GUIStyle(GUI.skin.textField);
        textFieldStyle.fontSize = 40;

        GUI.Label(new Rect(0, 0, Screen.width, 50), "Server URL", labelStyle);
        url = GUI.TextField(new Rect(0, 50, Screen.width, 100), url, textFieldStyle);

        if (GUI.Button(new Rect(0, 150, Screen.width / 2, 100), "Facebook", buttonStyle))
        {
            DoFacebookLogin();
            isFB = true;
        }
        if (GUI.Button(new Rect(Screen.width / 2, 150, Screen.width / 2, 100), "Twitter", buttonStyle))
        {
            DoTwitterLogin();
            isFB = false;
        }
        if (GUI.Button(new Rect(0, 250, Screen.width, 100), "Submit Token", buttonStyle))
        {
            string[] t = CurrentAccessToken();
            SubmitToken(t[0], t[1], url);
        }
        if (GUI.Button(new Rect(0, 350, Screen.width, 100), "Print Token", buttonStyle))
        {
            Debug.Log("Access Token: " + CurrentAccessToken());
        }
        GUI.TextField(new Rect(0, 450, Screen.width, 100), CurrentAccessToken()[0], textFieldStyle);
    }

    void DoFacebookLogin()
    {
        FacebookAndroid.loginWithPublishPermissions(new string[] {"email", "publish_actions"});
    }
    void DoTwitterLogin()
    {
        TwitterAndroid.showLoginDialog();
    }
    private string[] CurrentAccessToken()
    {
        if (isFB)
        {
            return new string[] {FacebookAndroid.getAccessToken(), ""};
        }
        else
        {
            // prime31 hasn't publicly exposed the token, but this is the official way to get it
            AndroidJavaClass unityPlayerClass = new AndroidJavaClass("com.unity3d.player.UnityPlayer");
            AndroidJavaObject activity = unityPlayerClass.GetStatic<AndroidJavaObject>("currentActivity");
            AndroidJavaObject sharedPreferences = activity.Call<AndroidJavaObject>("getSharedPreferences", "Twitter_Preferences", 0);

            string oauthToken = sharedPreferences.Call<string>("getString", "auth_key", null);
            string oauthTokenSecret = sharedPreferences.Call<string>("getString", "auth_secret_key", null);
            return new string[] {oauthToken, oauthTokenSecret};
        }
    }
/*    void TwitterRequestToken()
    {
        string consumerSecret = "4Re1gImPvYhBhGX2jL2rb5xjraF3q6pWwWWpmKIVNAXwtcrYFG";
        string oauthConsumerKey = "lnPEQhhVho6fu9dd6FqLfhQ2L";
        string oauthToken;
        string oauthTokenSecret;
        // Obtain request token - POST https://api.twitter.com/oauth/request_token (oauthCallback=oob)
        {
            string url = "https://api.twitter.com/oauth/request_token";
            string oauthCallback = "oob";
            string oauthNonce = Guid.NewGuid().ToString("n");
            string oauthSignature;
            string oauthSignatureMethod = "HMAC-SHA1";
            string oauthTimestamp = ((int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds).ToString();
            string oauthVersion = "1.0";
            
            oauthSignature = TwitterOauthSignature("POST", url,
                new string[] { "oauth_callback", "oauth_consumer_key", "oauth_nonce", "oauth_signature_method", "oauth_timestamp", "oauth_version" },
                new string[] {  oauthCallback  ,  oauthConsumerKey   ,  oauthNonce  ,  oauthSignatureMethod   ,  oauthTimestamp  ,  oauthVersion  },
                consumerSecret);

            string authHead = "OAuth "
                            + URLEncode("oauth_callback")           + "=\"" + URLEncode(oauthCallback)         + "\", "
                            + URLEncode("oauth_consumer_key")       + "=\"" + URLEncode(oauthConsumerKey)      + "\", "
                            + URLEncode("oauth_nonce")              + "=\"" + URLEncode(oauthNonce)            + "\", "
                            + URLEncode("oauth_signature")          + "=\"" + URLEncode(oauthSignature)        + "\", "
                            + URLEncode("oauth_signature_method")   + "=\"" + URLEncode(oauthSignatureMethod)  + "\", "
                            + URLEncode("oauth_timestamp")          + "=\"" + URLEncode(oauthTimestamp)        + "\", "
                            + URLEncode("oauth_version")            + "=\"" + URLEncode(oauthVersion)          + "\"";
            Dictionary<string, string> headers = new Dictionary<string, String>();
            headers.Add("Authorization", authHead);
            WWW www = new WWW(url, new byte[] { 0 }, headers);
            while (!www.isDone) ;
            print(www.text);
            print(www.error);
            int firstAmp, secondAmp;
            firstAmp = www.text.IndexOf("&");
            secondAmp = www.text.IndexOf("&", firstAmp + 1);
            oauthToken = www.text.Substring(www.text.IndexOf("oauth_token=") + "oauth_token=".Length, firstAmp - "oauth_token=".Length);
            oauthTokenSecret = www.text.Substring(www.text.IndexOf("oauth_token_secret=") + "oauth_token_secret=".Length, secondAmp - firstAmp - "oauth_token_secret=".Length - 1);

            twitterRequestToken = oauthToken;
        }
        // Redirect user - GET https://api.twitter.com/oauth/authenticate?oauth_token=____request_token____
        // Exchange request token for access token - POST https://api.twitter.com/oauth/access_token
/*        {
            string url = "https://api.twitter.com/oauth/access_token";
            string oauthNonce = Guid.NewGuid().ToString("n");
            string oauthSignature;
            string oauthSignatureMethod = "HMAC-SHA1";
            string oauthTimestamp = ((int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds).ToString();
            string oauthVersion = "1.0";

            oauthSignature = TwitterOauthSignature("POST", url,
                new string[] { "oauth_consumer_key", "oauth_nonce", "oauth_signature_method", "oauth_timestamp", "oauth_version" },
                new string[] {  oauthConsumerKey   ,  oauthNonce  ,  oauthSignatureMethod   ,  oauthTimestamp  ,  oauthVersion },
                consumerSecret);

            string authHead = "OAuth "
                            + URLEncode("oauth_consumer_key") + "=\"" + URLEncode(oauthConsumerKey) + "\", "
                            + URLEncode("oauth_nonce") + "=\"" + URLEncode(oauthNonce) + "\", "
                            + URLEncode("oauth_signature") + "=\"" + URLEncode(oauthSignature) + "\", "
                            + URLEncode("oauth_signature_method") + "=\"" + URLEncode(oauthSignatureMethod) + "\", "
                            + URLEncode("oauth_timestamp") + "=\"" + URLEncode(oauthTimestamp) + "\", "
                            + URLEncode("oauth_version") + "=\"" + URLEncode(oauthVersion) + "\"";
            Dictionary<string, string> headers = new Dictionary<string, String>();
            headers.Add("Authorization", authHead);
            WWW www = new WWW(url, new byte[] { 0 }, headers);
            while (!www.isDone) ;
            print(www.text);
            print(www.error);
            int firstAmp, secondAmp;
            firstAmp = www.text.IndexOf("&");
            secondAmp = www.text.IndexOf("&", firstAmp + 1);
            oauthToken = www.text.Substring(www.text.IndexOf("oauth_token=") + "oauth_token=".Length, firstAmp - "oauth_token=".Length);
            oauthTokenSecret = www.text.Substring(www.text.IndexOf("oauth_token_secret=") + "oauth_token_secret=".Length, secondAmp - firstAmp - "oauth_token_secret=".Length - 1);
        }

        // xAuth ******************************************************************
      // Request body - xAuth requires a few special parameters
        string xAuthMode = "client_auth";
        // TODO Make this prettier (%3D => '=', %3B => '&')
        byte[] body = Encoding.ASCII.GetBytes((
                "x_auth_mode"       + "%3D" + xAuthMode + "%3B"
              + "x_auth_password"   + "%3D" + password  + "%3B"
              + "x_auth_username"   + "%3D" + username
              ).ToCharArray());
        // HACK
        body = new byte[1] { 0 };

        // Build the request header
        string authorizationHeader = "OAuth ";
        string consumerKey = "kTjvF23EVAET42ZvkiIamqrI3"; // check dev.twitter.com/apps
        //consumerKey = "lnPEQhhVho6fu9dd6FqLfhQ2L";
        string consumerSecret = "uxGRyMA0aa1MgcWQssUfVXXSDpbX8xX1rmfcBwlvR1YhYzuAHM"; // check dev.twitter.com/apps
        //consumerSecret = "4Re1gImPvYhBhGX2jL2rb5xjraF3q6pWwWWpmKIVNAXwtcrYFG";
        //consumerSecret = "MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98";
        string nonce = Guid.NewGuid().ToString("n"); // wheeeeee (ToString("n") means numeric format - 32 hexits)
        string signatureMethod = "HMAC-SHA1";
        string timestamp = ((int) (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds).ToString();
        string oauthVersion = "1.0";
        string signature = TwitterOauthSignature("POST", "https://api.twitter.com/oauth/access_token",
            new string[] { "oauth_consumer_key", "oauth_consumer_secret", "oauth_nonce", "oauth_signature_method", "oauth_timestamp", "oauth_version", "x_auth_mode", "x_auth_password", "x_auth_username" },
            new string[] { consumerKey, consumerSecret, nonce, signatureMethod, timestamp, oauthVersion, xAuthMode, password, username },
            consumerSecret); // sigh

        authorizationHeader += URLEncode("oauth_consumer_key")      + "=\"" + URLEncode(consumerKey)        + "\", "
                             + URLEncode("oauth_consumer_secret")   + "=\"" + URLEncode(consumerSecret)     + "\", "
                             + URLEncode("oauth_nonce")             + "=\"" + URLEncode(nonce)              + "\", "
                             + URLEncode("oauth_signature")         + "=\"" + URLEncode(signature)          + "\", "
                             + URLEncode("oauth_signature_method")  + "=\"" + URLEncode(signatureMethod)    + "\", "
                             + URLEncode("oauth_timestamp")         + "=\"" + URLEncode(timestamp)          + "\", "
                             + URLEncode("oauth_version")           + "=\"" + URLEncode(oauthVersion)       + "\"";
        Dictionary<string, string> headers = new Dictionary<string, string>();
        headers.Add("Authorization", authorizationHeader);
        print("authorizationheader= " + authorizationHeader);
        print("signature= " + signature);

        WWW www = new WWW("https://api.twitter.com/oauth/access_token", body, headers);
        // TODO Handle errors (e.g. no Internet connectivity)
        // TODO Wait for www in a nicer way
        while (!www.isDone) ;
        print(www.text);
        print(www.error);
        print(www);
    }
    string OauthAuthHeader(string httpMethod, string url, string[] keys, string[] values)
    {
        for (int i = 0; i < keys.Length; i++)
        {
            keys[i] = URLEncode(keys[i]);
            values[i] = URLEncode(values[i]);
        }
        Array.Sort(keys, values);
        string authHeadString = "";
        for (int i = 0; i < keys.Length; i++)
        {
            authHeadString += keys[i] + "=\"" + values[i] + "\"";
            // If there are more key/value pairs, append an ampersand (&)
            if (i < keys.Length - 1)
            {
                authHeadString += "&";
            }
        }
        return authHeadString;
    }
    string TwitterOauthSignature(string httpMethod, string url, string[] keys, string[] values, string consumerSecret, string tokenSecret = "")
    {
        for (int i = 0; i < keys.Length; i++)
        {
            keys[i] = URLEncode(keys[i]);
            values[i] = URLEncode(values[i]);
        }
        Array.Sort(keys, values);
        string paramString = "";
        for (int i = 0; i < keys.Length; i++)
        {
            paramString += keys[i] + "=" + values[i];
            // If there are more key/value pairs, append an ampersand (&)
            if (i < keys.Length - 1)
            {
                paramString += "&";
            }
        }
        string sigBaseString = httpMethod.ToUpper() + "&" + URLEncode(url) + "&" + URLEncode(paramString);
        string sigKey = URLEncode(consumerSecret) + "&" + URLEncode(tokenSecret);
        HMACSHA1 sha = new HMACSHA1(Encoding.ASCII.GetBytes(sigKey));
        sha.Initialize();
        return System.Convert.ToBase64String(sha.ComputeHash(Encoding.ASCII.GetBytes(sigBaseString)));
    }*/
    void SubmitToken(string token, string secret, string url)
    {
        if (url.IndexOf('?') == -1)
        {
            url += "?client_token=" + token;
        }
        else
        {
            url += "&client_token=" + token;
        }

        // Must use WWWForm to force POST method
        WWWForm form = new WWWForm();
        form.AddField("client_token", token);
        // If there is a secret as well
        if (!secret.Equals(""))
        {
            url += "&client_secret=" + secret;
            form.AddField("client_secret", secret);
        }
        WWW www = new WWW(url, form);
    }
    string URLEncode(string str)
    {
        // Rolling our own URLEncode because none of the built-in C#/Unity encoders do quite the right thing
        string unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        StringBuilder result = new StringBuilder();

        foreach (char symbol in str) {
            if (unreservedChars.IndexOf(symbol) != -1)
            {
                result.Append(symbol);
            }
            else
            {
                result.Append('%' + String.Format("{0:X2}", (int)symbol));
            }
        }

        return result.ToString();
    }
}

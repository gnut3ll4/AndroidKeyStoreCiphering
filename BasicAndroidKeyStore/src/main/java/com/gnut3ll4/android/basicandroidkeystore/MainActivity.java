/*
 * Copyright 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.gnut3ll4.android.basicandroidkeystore;

import android.os.Bundle;
import android.support.v4.app.FragmentActivity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.example.android.basicandroidkeystore.R;
import com.gnut3ll4.android.common.logger.LogWrapper;
import com.gnut3ll4.android.common.logger.MessageOnlyLogFilter;
import com.gnut3ll4.android.common.logger.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;

import javax.crypto.Cipher;

public class MainActivity extends FragmentActivity {

    public final static String TAG = "MainActivity";
    public LogFragment mLogFragment;

    public KeyStoreHelper mKeyStoreHelper;

    private EditText editText;
    private Button button;

    private byte[] encryptedBytes;

    // You can store multiple key pairs in the Key Store.  The string used to refer to the Key you
    // want to store, or later pull, is referred to as an "alias" in this case, because calling it
    // a key, when you use it to retrieve a key, would just be irritating.
    public static final String ALIAS = "myKeyAlias";

    // Some sample data to sign, and later verify using the generated signature.
    public static final String SAMPLE_INPUT = "Hello, Android!";

    // Just a handy place to store the signature in between signing and verifying.
    public String mSignatureStr = null;


    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        editText = (EditText) findViewById(R.id.edittext);
        button = (Button) findViewById(R.id.button);

        mKeyStoreHelper = new KeyStoreHelper();
        mKeyStoreHelper.setAlias(ALIAS);
        initializeLogging();

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                try {

                    //Encrypt
                    KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                    ks.load(null);
                    Key key = ks.getKey(ALIAS, null);

                    if (key instanceof PrivateKey) {

                        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
                        cipher.init(Cipher.ENCRYPT_MODE, ks.getCertificate(ALIAS).getPublicKey());
                        encryptedBytes = cipher.doFinal(editText.getText().toString().getBytes());

                        Log.d(TAG, "Encrypted bytes : " + new String(encryptedBytes, "UTF-8"));
                    }

                    //Decrypt
                    PrivateKey privateKey = loadPrivateKey(ALIAS);
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    byte[] bytes = cipher.doFinal(encryptedBytes);

                    Log.d(TAG, "Decrypted string : " + new String(bytes, "UTF-8"));


                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        });

    }

    public PrivateKey loadPrivateKey(String alias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(ALIAS, null);
        return entry.getPrivateKey();
    }

    public ArrayList<String> getAliases() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

        keyStore.load(null, null);

        return Collections.list(keyStore.aliases());
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.btn_create_keys:
                try {
                    mKeyStoreHelper.createKeys(this);
                    Log.d(TAG, "Keys created");
                    return true;
                } catch (NoSuchAlgorithmException e) {
                    Log.w(TAG, "RSA not supported", e);
                } catch (InvalidAlgorithmParameterException e) {
                    Log.w(TAG, "No such provider: AndroidKeyStore");
                } catch (NoSuchProviderException e) {
                    Log.w(TAG, "Invalid Algorithm Parameter Exception", e);
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                }
                return true;
            case R.id.btn_sign_data:
                try {
                    mSignatureStr = mKeyStoreHelper.signData(SAMPLE_INPUT);
                } catch (KeyStoreException e) {
                    Log.w(TAG, "KeyStore not Initialized", e);
                } catch (UnrecoverableEntryException e) {
                    Log.w(TAG, "KeyPair not recovered", e);
                } catch (NoSuchAlgorithmException e) {
                    Log.w(TAG, "RSA not supported", e);
                } catch (InvalidKeyException e) {
                    Log.w(TAG, "Invalid Key", e);
                } catch (SignatureException e) {
                    Log.w(TAG, "Invalid Signature", e);
                } catch (IOException e) {
                    Log.w(TAG, "IO Exception", e);
                } catch (CertificateException e) {
                    Log.w(TAG, "Error occurred while loading certificates", e);
                }
                Log.d(TAG, "Signature: " + mSignatureStr);
                return true;

            case R.id.btn_verify_data:
                boolean verified = false;
                try {
                    if (mSignatureStr != null) {
                        verified = mKeyStoreHelper.verifyData(SAMPLE_INPUT, mSignatureStr);
                    }
                } catch (KeyStoreException e) {
                    Log.w(TAG, "KeyStore not Initialized", e);
                } catch (CertificateException e) {
                    Log.w(TAG, "Error occurred while loading certificates", e);
                } catch (NoSuchAlgorithmException e) {
                    Log.w(TAG, "RSA not supported", e);
                } catch (IOException e) {
                    Log.w(TAG, "IO Exception", e);
                } catch (UnrecoverableEntryException e) {
                    Log.w(TAG, "KeyPair not recovered", e);
                } catch (InvalidKeyException e) {
                    Log.w(TAG, "Invalid Key", e);
                } catch (SignatureException e) {
                    Log.w(TAG, "Invalid Signature", e);
                }
                if (verified) {
                    Log.d(TAG, "Data Signature Verified");
                } else {
                    Log.d(TAG, "Data not verified.");
                }
                return true;
        }
        return false;
    }

    /**
     * Create a chain of targets that will receive log data
     */
    public void initializeLogging() {
        // Using Log, front-end to the logging chain, emulates android.util.log method signatures.
        // Wraps Android's native log framework
        LogWrapper logWrapper = new LogWrapper();
        Log.setLogNode(logWrapper);

        // A filter that strips out everything except the message text
        MessageOnlyLogFilter msgFilter = new MessageOnlyLogFilter();
        logWrapper.setNext(msgFilter);

        // On screen logging via a fragment with a TextView
        mLogFragment = (LogFragment) getSupportFragmentManager().findFragmentById(R.id.log_fragment);
        msgFilter.setNext(mLogFragment.getLogView());
        Log.i(TAG, "Ready");
    }
}

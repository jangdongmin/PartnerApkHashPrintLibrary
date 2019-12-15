package com.bank;
    

//////////////////////////////////////////////////
//입력 

//////////////////////////////////////////////////
import com.ubikey.stock.UbikeyLibrary;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
//import com.ubikey.aidl.R;
import android.widget.TextView;

public class main extends Activity {

//	// 제휴사 코드
//	private static String CODE = "A009";
//	
//	// 제휴사 키
//	private static byte[] DK = {	(byte)0x50, (byte)0x51, (byte)0x52, (byte)0x53,
//									(byte)0x54, (byte)0x55, (byte)0x56, (byte)0x57,
//									(byte)0x58, (byte)0x59, (byte)0x5A, (byte)0x5B,
//									(byte)0x5C, (byte)0x5D, (byte)0x5E, (byte)0x5F};

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        setContentView(R.layout.main);        
        TextView tv_hash_data_1 = (TextView)findViewById(R.id.tv_hash_data_1);
        TextView tv_hash_data_2 = (TextView)findViewById(R.id.tv_hash_data_2);
        
        UbikeyLibrary lib = new UbikeyLibrary();
        
        if(lib.genHashData(this.getApplicationContext(), "UBIKeyLinkageSampleOnlyCert.apk", CODE, DK) == false) {
        	Log.d("ApkHashLibrary", "genHashData() Fail");
        }
        
        tv_hash_data_1.setText(lib.getHashData1());
        tv_hash_data_2.setText(lib.getHashData2());
        
        Log.d("ApkHashLibrary", "HashData1 : " + lib.getHashData1());
        Log.d("ApkHashLibrary", "HashData2 : " + lib.getHashData2());
        
        // 제휴앱의 상용APK의 변동사항이 있으면 (주)인포바인으로 HashData1 과 HashData2 의 값을 전달해 주시기 바랍니다. 
    }
    
    @Override
	public void onResume() {
		super.onResume();
	}

	@Override
	public void onPause() {
		super.onPause();
	}	
    
    
    @Override
    protected void onDestroy() {
		super.onDestroy();
    }
   
}
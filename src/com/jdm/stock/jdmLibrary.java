package com.jdm.stock;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.res.AssetManager;
import android.util.Log;

public class jdmLibrary {

	private Context mContext = null;

	private String HashData1 = "";
	private String HashData2 = "";

	public String getHashData1() {
		return HashData1;
	}
	
	public String getHashData2() {
		return HashData2;
	}
	
	//
	// [ 상호 인증 ]
	// ----------------------------------
	public boolean genHashData(Context context, String assetsApkFileName, String code, byte[] key) {
		mContext = context;
		File file = new File(context.getFilesDir(), "outFile");
		
		try {
			AssetManager am = context.getResources().getAssets();
			InputStream inputStream = am.open(assetsApkFileName);
			OutputStream outStream = new FileOutputStream(file);
		      // 읽어들일 버퍼크기를 메모리에 생성
		      byte[] buf = new byte[1024];
		      int len = 0;
		      // 끝까지 읽어들이면서 File 객체에 내용들을 쓴다
		      while ((len = inputStream.read(buf)) > 0){
		         outStream.write(buf, 0, len);
		      }
		      // Stream 객체를 모두 닫는다.
		      outStream.close();
		      inputStream.close();
		      
		} catch (IOException e1) {
			e1.printStackTrace();
			return false;
		}

		JARVerifierV3 jarv = new JARVerifierV3();
		jarv.verify(file, key);

		if(HashData1.equals("") == true && HashData2.equals("") == true) {
			return false;
		} else {
			return true;
		}
	}

	// ----------------------------------

	final class JARVerifierV3 {
		private boolean verify(File theFile, byte[] key) {
			try {
				JarFile jf = new JarFile(theFile, true);

				try {
					verify(jf, key);
					return true;
				} finally {
					jf.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}
		}

		JARVerifierV3() {
			buffer = new byte[8192];
		}

		private void verify(JarFile theJARFile, byte[] key) throws Exception {
			Enumeration<JarEntry> entries = theJARFile.entries();

			while (entries.hasMoreElements()) {
				verify(theJARFile, key, entries.nextElement());
			}

		}

		private byte[] readFromStream(InputStream pInputStream) {
			if (pInputStream == null) {
				return null;
			}

			int lBufferSize = 1024;
			byte[] lByteBuffer = new byte[lBufferSize];

			int lBytesRead = 0;

			ByteArrayOutputStream lByteArrayOutputStream = new ByteArrayOutputStream(
					lBufferSize * 2);

			try {
				while ((lBytesRead = pInputStream.read(lByteBuffer)) != -1) {
					lByteArrayOutputStream.write(lByteBuffer, 0, lBytesRead);
				}
			} catch (Throwable e) {
				e.printStackTrace(System.out);
			}

			byte[] lDataBytes = lByteArrayOutputStream.toByteArray();

			return lDataBytes;
		}

		private void verify(JarFile theJARFile, byte[] key, JarEntry theEntry) throws Exception {
			String hashkey = null;
			byte[] data = null;
			try {
				InputStream is = theJARFile.getInputStream(theEntry);

				if (theEntry.getName().equals("META-INF/CERT.RSA"))
				// if(theEntry.getName().equals("META-INF/CERT.SF"))
				{
					// ------------------------------------------------------------------------------
					// 1. 소유자 정보(제휴사 정보)
					// ------------------------------------------------------------------------------
					X509Certificate cert = getCertInfo();

//					String a = cert.toString();// 인증서
					String b = cert.getPublicKey().toString().toLowerCase();			// 공개키
					Log.e("1. 소유자 정보(제휴사 정보)","공개키:"+b);
					String c = cert.getSubjectDN().toString().toLowerCase();			// 소유자
					Log.e("1. 소유자 정보(제휴사 정보)","소유자:"+c);
					String d = cert.getIssuerX500Principal().toString().toLowerCase();	// 발급자
					Log.e("1. 소유자 정보(제휴사 정보)","발급자:"+d);
					String e = cert.getNotBefore().toString().toLowerCase();			// 유효기간 시작
					Log.e("1. 소유자 정보(제휴사 정보)","발급일:"+e);
					String f = cert.getNotAfter().toString().toLowerCase();				// 유효기간 종료
					Log.e("1. 소유자 정보(제휴사 정보)","만료일:"+f);
//					String sum = a + b + c + d + e + f;
					String sum = b + c + d + e + f;

					hashkey = new String(key);

					data = Base64_HMACSHA1(sum, hashkey); // hmac-sha1
//					String data1ToString = new String(data1);
					HashData1 = new String(data);
					Log.e("1. 소유자 정보(제휴사 정보)","data1ToString = "+HashData1);
					releaseByteArray(data);
					releaseString(hashkey);
					// ------------------------------------------------------------------------------

					// ------------------------------------------------------------------------------
					// 2. 2. 무결성 검사
					// ------------------------------------------------------------------------------
					String hex = bytesToHex(readFromStream(is));// 추출 //16진수 변경
					data = Base64_HMACSHA1(hex, hashkey); // hmac-sha1
//					String data2ToString = new String(data2);
					HashData2 = new String(data);
					Log.e("2. 무결성 검사","data2ToString = "+HashData2);
					releaseByteArray(data);
					releaseString(hashkey);
					// ------------------------------------------------------------------------------
				}

				while (is.read(buffer) != -1) {
				}

				ensureCertificates(theEntry);

			} catch (Exception e) {
				releaseByteArray(data);
				releaseString(hashkey);
				e.printStackTrace();
			}
		}

		String toBinary(byte[] bytes) {
			StringBuilder sb = new StringBuilder(bytes.length * Byte.SIZE);
			for (int i = 0; i < Byte.SIZE * bytes.length; i++)
				sb.append((bytes[i / Byte.SIZE] << i % Byte.SIZE & 0x80) == 0 ? '0'
						: '1');
			return sb.toString();
		}

		byte[] fromBinary(String s) {
			int sLen = s.length();
			byte[] toReturn = new byte[(sLen + Byte.SIZE - 1) / Byte.SIZE];
			char c;
			for (int i = 0; i < sLen; i++)
				if ((c = s.charAt(i)) == '1')
					toReturn[i / Byte.SIZE] = (byte) (toReturn[i / Byte.SIZE] | (0x80 >>> (i % Byte.SIZE)));
				else if (c != '0')
					throw new IllegalArgumentException();
			return toReturn;
		}

		private void ensureCertificates(JarEntry theEntry) throws Exception {
			if (!theEntry.getName().startsWith(META_INF)) {
				Certificate[] certificates = theEntry.getCertificates();

				if (certificates == null) {
					throw new SecurityException("No certificates: "
							+ theEntry.getName());
				}
			}
		}

		private byte[] buffer;
		private static final String META_INF = "META-INF/";
	}

	final protected char[] hexArray = "0123456789ABCDEF".toCharArray();

	private String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	private final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

	private byte[] Base64_HMACSHA1(String data, String key)
			throws java.security.SignatureException {
		byte[] rawHmac = null;

		try {
			// get an hmac_sha1 key from the raw key bytes
			SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(),
					HMAC_SHA1_ALGORITHM);

			// get an hmac_sha1 Mac instance and initialize with the signing key
			Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
			mac.init(signingKey);

			// compute the hmac on input data bytes
			rawHmac = mac.doFinal(data.getBytes());
		} catch (Exception e) {
			throw new SignatureException("Failed to generate HMAC : "
					+ e.getMessage());
		}

		// return rawHmac;
		byte[] buf = null;

		try {
			Class Base64 = Class.forName("org.apache.commons.codec.binary.Base64");
			Class[] parameterTypes = new Class[] { byte[].class };
			Method encodeBase64 = Base64.getMethod("encodeBase64", parameterTypes);
			buf = (byte[]) encodeBase64.invoke(Base64, rawHmac);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return buf;
	}

	private X509Certificate getCertInfo() {
		final PackageManager packageManager = mContext.getPackageManager();

		final List<PackageInfo> packageList = packageManager
				.getInstalledPackages(PackageManager.GET_SIGNATURES);

		for (PackageInfo p : packageList) {
			final String strVendor = p.packageName;
			if (mContext.getPackageName().equals(strVendor)) {
				final Signature[] arrSignatures = p.signatures;
				for (final Signature sig : arrSignatures) {
					/*
					 * Get the X.509 certificate.
					 */
					final byte[] rawCert = sig.toByteArray();
					InputStream certStream = new ByteArrayInputStream(rawCert);

					final CertificateFactory certFactory;
					final X509Certificate x509Cert;
					try {
						certFactory = CertificateFactory.getInstance("X509");
						x509Cert = (X509Certificate) certFactory
								.generateCertificate(certStream);
						return x509Cert;
					} catch (CertificateException e) {
						e.printStackTrace();
					}
				}
			}
		}
		return null;
	}

	private void releaseByteArray(byte[] buffer) {
		try {
			if (buffer != null) {
				for (int i = 0; i < buffer.length; i++) {
					buffer[i] = 0;
				}
				buffer = null;
			}
		} catch (Exception e) {
			buffer = null;
		}
	}

	private void releaseString(String str) {
		try {
			if (str != null || 0 < str.length()) {
				for (int i = 0; i < str.length(); i++) {
					str.replace(str.charAt(i), '0');
				}
				str = null;
			}
		} catch (Exception e) {
			str = null;
		}
	}
}

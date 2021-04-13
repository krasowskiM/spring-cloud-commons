/*
 * Copyright 2012-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.cloud.commons.httpclient;

import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.conn.DefaultHttpClientConnectionOperator;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.springframework.util.ReflectionUtils;

import javax.net.ssl.*;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.BDDAssertions.then;
import static org.springframework.cloud.commons.httpclient.ApacheHttpClientConnectionManagerFactory.HTTPS_SCHEME;
import static org.springframework.cloud.commons.httpclient.ApacheHttpClientConnectionManagerFactory.HTTP_SCHEME;

/**
 * @author Ryan Baxter
 * @author Michael Wirth
 */
public class DefaultApacheHttpClientConnectionManagerFactoryTests {

	@Test
	public void newConnectionManager() {
		HttpClientConnectionManager connectionManager = new DefaultApacheHttpClientConnectionManagerFactory()
				.newConnectionManager(false, 2, 6);
		then(((PoolingHttpClientConnectionManager) connectionManager).getDefaultMaxPerRoute()).isEqualTo(6);
		then(((PoolingHttpClientConnectionManager) connectionManager).getMaxTotal()).isEqualTo(2);
		Object pool = getField((connectionManager), "pool");
		then((Long) getField(pool, "timeToLive")).isEqualTo(new Long(-1));
		TimeUnit timeUnit = getField(pool, "timeUnit");
		then(timeUnit).isEqualTo(TimeUnit.MILLISECONDS);
	}

	@Test
	public void newConnectionManagerWithTTL() {
		HttpClientConnectionManager connectionManager = new DefaultApacheHttpClientConnectionManagerFactory()
				.newConnectionManager(false, 2, 6, 56L, TimeUnit.DAYS, null);
		then(((PoolingHttpClientConnectionManager) connectionManager).getDefaultMaxPerRoute()).isEqualTo(6);
		then(((PoolingHttpClientConnectionManager) connectionManager).getMaxTotal()).isEqualTo(2);
		Object pool = getField((connectionManager), "pool");
		then((Long) getField(pool, "timeToLive")).isEqualTo(new Long(56));
		TimeUnit timeUnit = getField(pool, "timeUnit");
		then(timeUnit).isEqualTo(TimeUnit.DAYS);
	}

	@Test
	@DisabledForJreRange(min = JRE.JAVA_16)
	public void newConnectionManagerWithSSL() {
		HttpClientConnectionManager connectionManager = new DefaultApacheHttpClientConnectionManagerFactory()
				.newConnectionManager(false, 2, 6);

		Lookup<ConnectionSocketFactory> socketFactoryRegistry = getConnectionSocketFactoryLookup(connectionManager);
		then(socketFactoryRegistry.lookup("https")).isNotNull();
		then(getX509TrustManager(socketFactoryRegistry).getAcceptedIssuers()).isNotNull();
	}

	@Test
	public void newConnectionManagerWithCustomSSLContext() {
		try {
			//given
			KeyStore dummyKeystore = KeyStore.getInstance("JKS");
			dummyKeystore.load(this.getClass().getResourceAsStream("/test_cert.jks"), "123".toCharArray());

			SSLContext customContext = SSLContextBuilder.create()
					.setProtocol("TLSv1.2")
					.loadKeyMaterial(dummyKeystore, "123".toCharArray())
					.build();
			//when
			HttpClientConnectionManager connectionManager = new DefaultApacheHttpClientConnectionManagerFactory()
					.newConnectionManager(false, 2, 6, 10, TimeUnit.SECONDS,
							RegistryBuilder.create()
									.register(HTTP_SCHEME, PlainConnectionSocketFactory.INSTANCE)
									.register(HTTPS_SCHEME, new SSLConnectionSocketFactory(customContext)));
			//then
			Lookup<ConnectionSocketFactory> socketFactoryRegistry = getConnectionSocketFactoryLookup(connectionManager);
			then(socketFactoryRegistry.lookup("https")).isNotNull();
			then(getX509TrustManager(socketFactoryRegistry).getAcceptedIssuers()).isNotNull();

			X509ExtendedKeyManager x509KeyManager = getX509KeyManager(socketFactoryRegistry);
			X509ExtendedKeyManager customKeyManager = getCustomKeyManager(customContext);
			assertThat(x509KeyManager).isEqualTo(customKeyManager);
		} catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException | CertificateException | IOException | UnrecoverableKeyException e) {
			e.printStackTrace();
		}
	}

	@Test
	@DisabledForJreRange(min = JRE.JAVA_16)
	public void newConnectionManagerWithDisabledSSLValidation() {
		HttpClientConnectionManager connectionManager = new DefaultApacheHttpClientConnectionManagerFactory()
				.newConnectionManager(true, 2, 6);

		Lookup<ConnectionSocketFactory> socketFactoryRegistry = getConnectionSocketFactoryLookup(connectionManager);
		then(socketFactoryRegistry.lookup("https")).isNotNull();
		then(getX509TrustManager(socketFactoryRegistry).getAcceptedIssuers()).isNull();
	}

	private Lookup<ConnectionSocketFactory> getConnectionSocketFactoryLookup(
			HttpClientConnectionManager connectionManager) {
		DefaultHttpClientConnectionOperator connectionOperator = getField(connectionManager, "connectionOperator");
		return getField(connectionOperator, "socketFactoryRegistry");
	}

	private SSLContextSpi getSslContextSpi(Lookup<ConnectionSocketFactory> socketFactoryRegistry) {
		ConnectionSocketFactory connectionSocketFactory = socketFactoryRegistry.lookup("https");
		SSLSocketFactory sslSocketFactory = getField(connectionSocketFactory, "socketfactory");
		return getField(sslSocketFactory, "context");
	}

	private X509ExtendedKeyManager getCustomKeyManager(SSLContext sslContext) {
		SSLContextSpi sslContextSpi = getField(sslContext, "contextSpi");
		return getField(sslContextSpi, "keyManager");
	}

	private X509TrustManager getX509TrustManager(Lookup<ConnectionSocketFactory> socketFactoryRegistry) {
		SSLContextSpi sslContext = getSslContextSpi(socketFactoryRegistry);
		return getField(sslContext, "trustManager");
	}

	private X509ExtendedKeyManager getX509KeyManager(Lookup<ConnectionSocketFactory> socketFactoryRegistry) {
		SSLContextSpi sslContext = getSslContextSpi(socketFactoryRegistry);
		return getField(sslContext, "keyManager");
	}

	@SuppressWarnings("unchecked")
	protected <T> T getField(Object target, String name) {
		Field field = ReflectionUtils.findField(target.getClass(), name);
		if (field == null) {
			throw new IllegalArgumentException("Can not find field " + name + " in " + target.getClass());
		}
		ReflectionUtils.makeAccessible(field);
		Object value = ReflectionUtils.getField(field, target);
		return (T) value;
	}

}

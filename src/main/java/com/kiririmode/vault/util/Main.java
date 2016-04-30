package com.kiririmode.vault.util;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.stream.Collectors;

import com.kiririmode.vault.cmd.SimpleCommandLineParser;

/**
 * <code>java -jar jar-${version}.jar -prop <property file path> -keystore
 * <keystore path>
 * 
 * @author kiririmode
 *
 */
public class Main {

	/** KeyStore の形式 */
	private static final String KEYSTORE_TYPE = "JCEKS";
	/** KeyStore で保持する秘匿情報に対して適用する暗号化アルゴリズム */
	private static final String ENCRYPT_ALGORITHM = "AES/CBC/PKCS5Padding";

	/** キーストアのパスを指定するためのコマンドラインオプション用キー */
	private static final String KEY_KEYSTORE_PATH = "keystore";
	/** 秘匿情報を格納したプロパティファイルのパスを指定するためのコマンドラインオプション用キー */
	private static final String KEY_PROPERTY_PATH = "prop";
	/** 暗号化用の秘密鍵や初期化ベクトルを定義したプロパティファイルのパスを指定するためのコマンドラインオプション用キー */
	private static final String KEY_VAULT_PROPERTY_PATH = "vault";

	private static final String KEY_VAULT_IV = "vault.iv";
	private static final String KEY_VAULT_KEY = "vault.key";

	public static void main(String[] args) throws Exception {

		try {
			// コマンドライン引数のパース
			SimpleCommandLineParser parser = new SimpleCommandLineParser(args);
			Map<String, String> optMap = parser.parseOption(KEY_KEYSTORE_PATH, KEY_PROPERTY_PATH, KEY_VAULT_PROPERTY_PATH);

			// コマンドラインで指定された値を保持
			String keyStorePath = Objects.requireNonNull(optMap.get(KEY_KEYSTORE_PATH),
					"-keystore keystorePath is missing");
			String propertyPath = Objects.requireNonNull(optMap.get(KEY_PROPERTY_PATH),
					"-prop propertyPath is missing");
			String vaultPropertyPath = Objects.requireNonNull(optMap.get(KEY_VAULT_PROPERTY_PATH),
					"-vault propertyPath is missing");
			Console console = Objects.requireNonNull(System.console(), "console cannot be retrieved");

			// Vault の秘密鍵等を保持するプロパティファイル
			Properties vaultProp = readProperties(vaultPropertyPath);
			char[] password = console.readPassword("keystore password: ");
			KeyStoreVault vault = new KeyStoreVault(keyStorePath, new String(password), KEYSTORE_TYPE,
					ENCRYPT_ALGORITHM, vaultProp.getProperty(KEY_VAULT_KEY), vaultProp.getProperty(KEY_VAULT_IV));

			// 秘匿情報を保持するプロパティファイル
			Properties secretProp = readProperties(propertyPath);
			for (String alias : secretProp.stringPropertyNames()) {
				vault.store(alias, secretProp.getProperty(alias));
			}

		} catch (NullPointerException e) {
			System.err.println(e.getMessage());
		}
	}

	static Properties readProperties(String filePath) throws IOException {
		Properties prop = null;
		try (BufferedReader br = Files.newBufferedReader(new File(filePath).toPath())) {
			prop = new Properties();
			prop.load(br);
		}
		return prop;
	}
}

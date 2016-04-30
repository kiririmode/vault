package com.kiririmode.vault.cmd;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * コマンドライン引数の簡易パーサ。
 * 以下を前提として、コマンドラインを解析する。
 * <ul>
 *   <li> オプション名は一度のみ出現する (同一のオプション名が複数回出現しない)
 *  </ul>
 * 
 * @author kiririmode
 *
 */
public class SimpleCommandLineParser {

	List<String> args;

	public SimpleCommandLineParser(String ... args) {
		this.args = new ArrayList<>(Arrays.asList(args));
	}

	public Map<String, String> parseOption(String... optKeys) {

		Map<String, String> optMap = new HashMap<>();

		for (String optKey : optKeys) {
			for (int i = 0; i < args.size(); i++) {
				if (args.get(i).equals("-" + optKey)) {
					args.remove(i);
					
					String value = null;
					if (i < args.size() && ! args.get(i).startsWith("-")) {
						value = args.remove(i);
					}
					optMap.put(optKey, value);
					break;
				}
			}
			
		}
		return optMap;
	}
	
	public String[] remainingArguments() {
		return args.toArray(new String[] {});
	}
}

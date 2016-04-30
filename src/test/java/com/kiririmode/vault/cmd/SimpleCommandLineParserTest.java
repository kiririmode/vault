package com.kiririmode.vault.cmd;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import java.util.Map;

import org.junit.Test;

public class SimpleCommandLineParserTest {
	
	@Test
	public void test() {
		SimpleCommandLineParser sut = new SimpleCommandLineParser("-opt1", "hoge", "-opt2", "fuga", "posarg1");
		Map<String, String> optMap = sut.parseOption("opt1", "opt2");
		
		assertThat(optMap.get("opt1"), is("hoge"));
		assertThat(optMap.get("opt2"), is("fuga"));
		assertThat(sut.remainingArguments(), is(new String[] {"posarg1"}));
	}
	
	@Test
	public void test2() {
		SimpleCommandLineParser sut = new SimpleCommandLineParser("-opt1", "hoge", "-opt2", "fuga");
		Map<String, String> optMap = sut.parseOption("opt1", "opt2");
		
		assertThat(optMap.get("opt1"), is("hoge"));
		assertThat(optMap.get("opt2"), is("fuga"));
		assertThat(sut.remainingArguments(), is(new String[] {}));
	}

	@Test
	public void test3() {
		SimpleCommandLineParser sut = new SimpleCommandLineParser("-dummy", "dummy", "-opt1", "hoge", "-opt2");
		Map<String, String> optMap = sut.parseOption("opt1", "opt2");
		
		assertThat(optMap.get("opt1"), is("hoge"));
		assertThat(optMap.get("opt2"), is(nullValue()));
		assertThat(sut.remainingArguments(), is(new String[] {"-dummy", "dummy"}));
	}
}

if [ KlassInit.java -nt KlassInit.class ]; then
	build/macosx-aarch64-server-slowdebug/images/jdk/bin/javac -cp ../jtreg-8.2.1+1/lib/junit-platform-console-standalone-1.14.2.jar:. KlassInit.java
fi

build/macosx-aarch64-server-slowdebug/images/jdk/bin/java -cp ../jtreg-8.2.1+1/lib/junit-platform-console-standalone-1.14.2.jar:. \
	-Xcomp \
	-XX:+PrintCompilation \
	-XX:+PrintCompilation2 \
	-XX:-TieredCompilation \
	-XX:+CIPrintCompilerName \
	-XX:+PrintAssembly \
	-XX:+PrintStubCode \
	-XX:+TraceDeoptimization \
	-Xlog:class+init=trace \
	-XX:+LogCompilation \
	'-XX:CompileCommand=exclude,KlassInit$1TestClass.<clinit>' \
	'-XX:CompileCommand=print,KlassInit.lambda$testReleaseAtKlassInitInvokeStatic1$0' \
	KlassInit \
2>&1 | stdbuf -o0 tee log-KlassInit

echo \
	-Xcomp \
	-XX:+PrintAssembly \
	-Xlog:continuations=trace \
	'-XX:CompileCommand=exclude,KlassInit$1TestClass.<clinit>,255' \
	-XX:TieredStopAtLevel=1 \
	-XX:CompileCommand=exclude,KlassInit*,* \
	-XX:+CompilerDirectivesIgnoreCompileCommands \
	'-XX:CompileCommand=exclude,KlassInit::lambda*' '-XX:CompileCommand=exclude,KlassInit3269Lambda*::run' -XX:CompileCommand=exclude,KlassInitDriver::foo \
	-Xbatch \
	-XX:TieredStopAtLevel=4 \
	-Xint \

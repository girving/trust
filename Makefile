all: bundle.js

bundle.js: trusty.js
	browserify -o $@ $^

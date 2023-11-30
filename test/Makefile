.PHONY:default clean test_app

default: test_app
	pytest -s

test_app:
	make -C app

clean:
	make -C app clean
	rm -rf __pycache__

.PHONY:default clean test_app

default: test_app
	pytest -s

app_dir=syscall uprobe_c

test_app:
	for dir in $(app_dir); do \
	    make -C $$dir ;\
	done

clean:
	for dir in $(app_dir); do \
	    make -C $$dir clean;\
	done
	rm -rf __pycache__

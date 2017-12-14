install:
	pip install .

reinstall:
	pip uninstall tc-shortener -y
	pip install .

setup:
	@pip install -e .[tests]

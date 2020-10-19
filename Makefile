test:
	pytest

# ensure this passes before commiting
check:
	black --check seedweed
	isort --check seedweed
	flake8 seedweed

fix:
	black seedweed
	isort seedweed

clean:
	rm -rf venv **/__pycache__ dist

vectors:
	mkdir -p data
	venv/bin/generate-seedweed-test-vectors > data/test-vectors.csv

setup:
	virtualenv venv
	venv/bin/pip install -U pip
	venv/bin/pip install -U -r dev-requirements.txt
	venv/bin/flit install --symlink

setup-ci:
	python -m pip install --upgrade pip setuptools wheel
	python -m pip install --upgrade -r dev-requirements.txt

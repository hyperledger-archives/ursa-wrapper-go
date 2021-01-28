.PHONY: all
all: test

.PHONY: test
test:
	@scripts/test.sh

.PHONY: ci-images
ci-images:
	@cd .github/workflows/build && docker build -f Dockerfile.base-ursa -t m00sey/base-ursa:latest .
	@docker push m00sey/base-ursa:latest
	@cd .github/workflows/build && docker build -f Dockerfile.ursa_0.3.4 -t m00sey/ursa_0.3.4:latest .
	@docker push m00sey/ursa_0.3.4:latest
	@cd .github/workflows/build && docker build -f Dockerfile.ursa_0.3.2 -t m00sey/ursa_0.3.2:latest .
	@docker push m00sey/ursa_0.3.2:latest

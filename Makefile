.PHONY: setup up down test red blue-agent isolation dev
setup:        ## generate strong secrets into .env
	./scripts/gen_env.sh
up:           ## start the full stack (dashboard on http://localhost:8080)
	docker compose up --build -d
down:
	docker compose down
test:         ## run the gateway + sandbox test-suite
	cd gateway && python -m pytest -q
red:          ## run the automated red-team campaign through the gateway
	docker compose --profile tools run --rm red-runner --mode enforce
blue-agent:   ## stream alerts + audit-integrity as JSON lines (SIEM-friendly)
	docker compose --profile monitor up blue-agent
isolation:    ## prove the red zone cannot reach the LLM, DB or internet
	./scripts/verify_isolation.sh

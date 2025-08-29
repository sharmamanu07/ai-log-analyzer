pipeline {
    agent any

    environment {
        COMPOSE_FILE = "docker-compose.yml"
    }

    triggers {
        // Trigger on each git push (SCM polling or webhook)
        pollSCM('H/2 * * * *') // polls every 2 minutes
        // alternatively: use GitHub/GitLab webhook for instant builds
    }

    stages {
        stage('Checkout Code') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/sharmamanu07/ai-log-analyzer.git'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker compose -f ${COMPOSE_FILE} build'
            }
        }

        stage('Run Tests') {
            steps {
                sh '''
                echo "Add your test commands here"
                # Example: docker compose run --rm log-analyzer pytest
                '''
            }
        }

        stage('Deploy Application') {
            steps {
                sh '''
                docker compose -f ${COMPOSE_FILE} down
                docker compose -f ${COMPOSE_FILE} up -d --build
                '''
            }
        }
    }

    post {
        success {
            echo "✅ Deployment successful. Log Analyzer is running at port 8501."
        }
        failure {
            echo "❌ Build or deployment failed. Check logs."
        }
    }
}

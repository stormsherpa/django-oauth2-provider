pipeline {
  agent {
    label "python"
  }
  stages {
    stage('Virtualenv'){
      steps {
        sh '/usr/bin/virtualenv toxtest -p /usr/bin/python3'
        sh 'toxtest/bin/pip install tox==3.28.0 setuptools pathlib2'
      }
    }
    stage('Test 3.11'){
      parallel {
        stage('Unit Test Django 3.2'){
          steps {
            sh 'toxtest/bin/tox -e py3.11-django{3.2}'
          }
        }
        stage('Unit Test Django 4.0'){
          steps {
            sh 'toxtest/bin/tox -e py3.11-django{4.0}'
          }
        }
        stage('Unit Test Django 4.1'){
          steps {
            sh 'toxtest/bin/tox -e py3.11-django{4.1}'
          }
        }
        stage('Unit Test Django 4.2'){
          steps {
            sh 'toxtest/bin/tox -e py3.11-django{4.2}'
          }
        }
      }
    }
    stage('Test 3.12'){
      parallel {
        stage('Unit Test Django 3.2'){
          steps {
            sh 'toxtest/bin/tox -e py3.12-django{3.2}'
          }
        }
        stage('Unit Test Django 4.0'){
          steps {
            sh 'toxtest/bin/tox -e py3.12-django{4.0}'
          }
        }
        stage('Unit Test Django 4.1'){
          steps {
            sh 'toxtest/bin/tox -e py3.12-django{4.1}'
          }
        }
        stage('Unit Test Django 4.2'){
          steps {
            sh 'toxtest/bin/tox -e py3.12-django{4.2}'
          }
        }
      }
    }
  }
  post {
    cleanup {
      cleanWs()
    }
  }
}

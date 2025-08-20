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
            sh 'toxtest/bin/tox -e py311-django{32}'
          }
        }
        stage('Unit Test Django 4.0'){
          steps {
            sh 'toxtest/bin/tox -e py311-django{40}'
          }
        }
        stage('Unit Test Django 4.1'){
          steps {
            sh 'toxtest/bin/tox -e py311-django{41}'
          }
        }
        stage('Unit Test Django 4.2'){
          steps {
            sh 'toxtest/bin/tox -e py311-django{42}'
          }
        }
      }
    }
    stage('Test 3.12'){
      parallel {
        stage('Unit Test Django 3.2'){
          steps {
            sh 'toxtest/bin/tox -e py312-django{32}'
          }
        }
        stage('Unit Test Django 4.0'){
          steps {
            sh 'toxtest/bin/tox -e py312-django{40}'
          }
        }
        stage('Unit Test Django 4.1'){
          steps {
            sh 'toxtest/bin/tox -e py312-django{41}'
          }
        }
        stage('Unit Test Django 4.2'){
          steps {
            sh 'toxtest/bin/tox -e py312-django{42}'
          }
        }
      }
    }
    stage('Test 3.13'){
      parallel {
        stage('Unit Test Django 4.1'){
          steps {
            sh 'toxtest/bin/tox -e py313-django{41}'
          }
        }
        stage('Unit Test Django 4.2'){
          steps {
            sh 'toxtest/bin/tox -e py313-django{42}'
          }
        }
        stage('Unit Test Django 5.0'){
          steps {
            sh 'toxtest/bin/tox -e py313-django{50}'
          }
        }
        stage('Unit Test Django 5.1'){
          steps {
            sh 'toxtest/bin/tox -e py313-django{51}'
          }
        }
        stage('Unit Test Django 5.2'){
          steps {
            sh 'toxtest/bin/tox -e py313-django{52}'
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

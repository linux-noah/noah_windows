node {
  stage("Clone Repository") {
    checkout scm
      sh "git clean -fx"
  }

  stage("Build") {
    sh '''mkdir -p build
      cd build
      cmake -DCMAKE_BUILD_TYPE=Release ..
      make'''
  }

  stage("Test") {
    sh '''cd build
      make test ARGS=-V'''
  }

  notifyBuild("test2")
}

def notifyBuild(String buildStatus) {

  buildStatus.result = buildStatus ?: 'SUCCESSFUL'

  def colorName = 'RED'
  def colorCode = '#FF0000'
  def subject = "${buildStatus}: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]'"
  def summary = "${subject} (${env.BUILD_URL})"


  slackSend message: buildStatus
}

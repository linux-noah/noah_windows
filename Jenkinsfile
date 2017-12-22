node {
  try {
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
  } catch (e) { 
    currentBuild.result = "FAILED"
    throw e
  } finally {
    notifyBuild(currentBuild.result)
  }
}

def notifyBuild(String buildStatus) {

  buildStatus.result = buildStatus ?: 'SUCCESSFUL'

  def colorName = 'RED'
  def colorCode = '#FF0000'
  def subject = "${buildStatus}: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]'"
  def summary = "${subject} (${env.BUILD_URL})"

  // Override default values based on build status
  if (buildStatus == 'STARTED') {
    color = 'YELLOW'
    colorCode = '#FFFF00'
  } else if (buildStatus == 'SUCCESSFUL') {
    color = 'GREEN'
    colorCode = '#00FF00'
  } else {
    color = 'RED'
    colorCode = '#FF0000'
  }

  slackSend (color: colorCode, message: summary)
}

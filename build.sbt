lazy val root = (project in file(".")).
  settings(
    name := "snmpbf",
    version := "0.1",
    scalaVersion := "2.11.8",
    cancelable in Global := true,

    scalacOptions ++= Seq("-deprecation", "-feature"),

    libraryDependencies += "org.scalactic" %% "scalactic" % "2.2.6",
    libraryDependencies += "org.scalatest" %% "scalatest" % "2.2.6" % "test"
  )

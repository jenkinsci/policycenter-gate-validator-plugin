# policycenter-gate-validator
================================================
The Policy Center Gate Validator, a jenkins plugin, is to abort or continue the automated build and deployment pipeline based on the status of policy gates that have been configured inside of Policy Center.  This allows Jenkins to automate the continuous release / continuous deployment pipeline with acceptance policies defined in Policy Center for each step along the way.

This project contains a client for the Parasoft PolicyCenter REST API via Jenkins.

Prerequisites for building:
--------------------------
 - Java 6 JDK
 - Maven 3

To build:
---------

mvn clean install

To run:
-------

mvn hpi:run


To perform a release:
--------------------

mvn release:prepare release:perform

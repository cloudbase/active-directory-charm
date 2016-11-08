# Overview

This charm deploys a Windows Active Directory forest. Active Directory (AD) is a directory service that Microsoft developed for Windows domain networks and is included in most Windows Server operating systems as a set of processes and services.

An Active Directory deployment is a core component for various Windows failover, clustering or live migration scenarios. Hyper-V, Cinder, Exchange, SMB, Failover-Cluster, Microsoft SQL Server Always On or VDI charms use Active Directory for centralized user, authentication, network and resource management.

As Active Directory uses Lightweight Directory Access Protocol (LDAP) versions 2 and 3, Kerberos and DNS protocols, it can easily interact wit Unix-based services.

# Configuration

In order to deploy Active Directory charm, the following configuration options are mandatory:

- `administrator-password`, used to set the default Administrator password;
- `safe-mode-password`, used to set the password for the Administrator account when the computer is started in Safe Mode or a variant of Safe Mode, such as "Directory Services Restore Mode";
- `domain-user`, the name of the default domain user that the charm will create. This user will be granted with administrative privileges as well;
- `domain-user-password`, the password for the `domain-user`;
- `domain-name`, the fully qualified domain name.

# Usage

How to deploy the charm:

    juju deploy cs:~cloudbaseit/active-directory

How to add a relation with another charm:

    juju add-relation active-directory <another_deployed_charm>

## Scale out Usage

If another unit is added, another Domain Controller instance will be deployed.

How to add another unit:

    juju add-unit active-directory

## Scale down usage

When a unit is destroyed, an Active Directory controller is demoted and the node will be destroyed.

How to destroy a unit:

    juju destroy-unit active-directory/<unit-number>

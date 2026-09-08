# Cible SSH volontairement vulnérable (mot de passe faible), isolée dans son
# propre conteneur sur un réseau Docker privé, dans le seul but de générer un
# vrai flux d'authentification à surveiller. Aucune machine tierce n'est
# jamais visée : tout le trafic reste interne à ce projet.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server rsyslog \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /var/log

# Compte volontairement faible, pour la démonstration de brute-force.
RUN useradd -m -s /bin/bash admin && echo "admin:changeme123" | chpasswd

RUN sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config \
    && sed -i 's/#SyslogFacility AUTH/SyslogFacility AUTH/' /etc/ssh/sshd_config \
    && sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]


# Ubuntu 20.04 (Focal) inclut OpenSSL 1.1.1 nativement
FROM ubuntu:20.04
 
# Eviter les prompts interactifs pendant l'installation
ENV DEBIAN_FRONTEND=noninteractive
 
# Mise à jour et installation d'OpenSSL 1.1.1 + outils utiles
RUN apt-get update && apt-get install -y \
    openssl \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*
 
# Vérification de la version installée
RUN openssl version
 
# Répertoire de travail pour vos fichiers/certificats
WORKDIR /workspace
 
CMD ["/bin/bash"]
 
"""stack_signatures.py — curated dependency-coordinate -> framework signature
table.

Maps a parsed Dependency's (ecosystem, name) to a human-readable framework
label and category. This answers "which actual framework/library is this
project built on" generically across every ecosystem manifest_parsers.py
understands — Java, Node, Python, Go, Ruby, PHP, .NET, Rust — not just the
two stacks (Java/Angular) ast_struct.py's tree-sitter pass can structurally
parse.

Deliberately incomplete, same as ast_struct.py's annotation vocabulary was:
coverage grows over time. The difference is the input space here (dependency
coordinates, a closed and well-documented set per package registry) is far
more tractable to grow than an open-ended annotation-name vocabulary.
Anything not in SIGNATURES still surfaces in scan output as an "unrecognized"
dependency rather than silently vanishing — the direct fix for the reported
bug's "0 counts, none flagged" failure mode.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Optional, Tuple

Signature = Dict[str, str]

SIGNATURES: List[Signature] = [
    # --- Java / Maven & Gradle ------------------------------------------
    {"ecosystem": "maven", "match": "org.springframework:*", "label": "Spring Framework", "category": "web-framework"},
    {"ecosystem": "maven", "match": "org.springframework.boot:*", "label": "Spring Boot", "category": "web-framework"},
    {"ecosystem": "maven", "match": "org.springframework.security:*", "label": "Spring Security", "category": "security"},
    {"ecosystem": "maven", "match": "org.springframework.data:*", "label": "Spring Data", "category": "orm"},
    {"ecosystem": "maven", "match": "org.jboss.resteasy:*", "label": "JBoss RESTEasy (JAX-RS)", "category": "rest-framework"},
    {"ecosystem": "maven", "match": "javax.ws.rs:*", "label": "JAX-RS", "category": "rest-framework"},
    {"ecosystem": "maven", "match": "jakarta.ws.rs:*", "label": "JAX-RS (Jakarta)", "category": "rest-framework"},
    {"ecosystem": "maven", "match": "javax.servlet:*", "label": "Java Servlet/JSP", "category": "web-framework"},
    {"ecosystem": "maven", "match": "jakarta.servlet:*", "label": "Java Servlet/JSP", "category": "web-framework"},
    {"ecosystem": "maven", "match": "javax.ejb:*", "label": "EJB", "category": "web-framework"},
    {"ecosystem": "maven", "match": "jakarta.ejb:*", "label": "EJB (Jakarta)", "category": "web-framework"},
    {"ecosystem": "maven", "match": "org.jboss.ejb3:*", "label": "JBoss EJB3", "category": "web-framework"},
    {"ecosystem": "maven", "match": "org.apache.struts:*", "label": "Apache Struts (legacy MVC)", "category": "web-framework"},
    {"ecosystem": "maven", "match": "org.apache.axis2:*", "label": "Apache Axis2 SOAP", "category": "xml-soap"},
    {"ecosystem": "maven", "match": "org.apache.axis:*", "label": "Apache Axis SOAP", "category": "xml-soap"},
    {"ecosystem": "maven", "match": "org.apache.cxf:*", "label": "Apache CXF SOAP/REST", "category": "xml-soap"},
    {"ecosystem": "maven", "match": "org.drools:*", "label": "Drools rules engine", "category": "rules-engine"},
    {"ecosystem": "maven", "match": "org.kie:*", "label": "KIE / Drools rules engine", "category": "rules-engine"},
    {"ecosystem": "maven", "match": "org.jbpm:*", "label": "jBPM workflow engine", "category": "rules-engine"},
    {"ecosystem": "maven", "match": "org.hibernate*:*", "label": "Hibernate ORM", "category": "orm"},
    {"ecosystem": "maven", "match": "javax.persistence:*", "label": "JPA", "category": "orm"},
    {"ecosystem": "maven", "match": "jakarta.persistence:*", "label": "JPA (Jakarta)", "category": "orm"},
    {"ecosystem": "maven", "match": "com.oracle.database.jdbc:*", "label": "Oracle JDBC driver", "category": "database-driver"},
    {"ecosystem": "maven", "match": "com.oracle*:ojdbc*", "label": "Oracle JDBC driver", "category": "database-driver"},
    {"ecosystem": "maven", "match": "mysql:mysql-connector-java", "label": "MySQL JDBC driver", "category": "database-driver"},
    {"ecosystem": "maven", "match": "com.mysql:mysql-connector-j", "label": "MySQL JDBC driver", "category": "database-driver"},
    {"ecosystem": "maven", "match": "org.postgresql:postgresql", "label": "PostgreSQL JDBC driver", "category": "database-driver"},
    {"ecosystem": "maven", "match": "org.apache.logging.log4j:*", "label": "Log4j 2", "category": "logging"},
    {"ecosystem": "maven", "match": "log4j:log4j", "label": "Log4j 1.x (legacy)", "category": "logging"},
    {"ecosystem": "maven", "match": "org.slf4j:*", "label": "SLF4J", "category": "logging"},
    {"ecosystem": "maven", "match": "junit:*", "label": "JUnit", "category": "testing"},
    {"ecosystem": "maven", "match": "org.junit*:*", "label": "JUnit", "category": "testing"},

    # --- npm / Node -------------------------------------------------------
    {"ecosystem": "npm", "match": "@angular/core", "label": "Angular", "category": "web-framework"},
    {"ecosystem": "npm", "match": "react", "label": "React", "category": "web-framework"},
    {"ecosystem": "npm", "match": "vue", "label": "Vue.js", "category": "web-framework"},
    {"ecosystem": "npm", "match": "express", "label": "Express.js", "category": "rest-framework"},
    {"ecosystem": "npm", "match": "@nestjs/core", "label": "NestJS", "category": "rest-framework"},
    {"ecosystem": "npm", "match": "fastify", "label": "Fastify", "category": "rest-framework"},
    {"ecosystem": "npm", "match": "koa", "label": "Koa", "category": "rest-framework"},
    {"ecosystem": "npm", "match": "next", "label": "Next.js", "category": "web-framework"},
    {"ecosystem": "npm", "match": "mongoose", "label": "Mongoose (MongoDB ODM)", "category": "orm"},
    {"ecosystem": "npm", "match": "sequelize", "label": "Sequelize ORM", "category": "orm"},
    {"ecosystem": "npm", "match": "typeorm", "label": "TypeORM", "category": "orm"},
    {"ecosystem": "npm", "match": "prisma", "label": "Prisma ORM", "category": "orm"},
    {"ecosystem": "npm", "match": "jsonwebtoken", "label": "JWT (jsonwebtoken)", "category": "security"},
    {"ecosystem": "npm", "match": "passport", "label": "Passport.js auth", "category": "security"},

    # --- Python -------------------------------------------------------
    {"ecosystem": "pypi", "match": "flask", "label": "Flask", "category": "rest-framework"},
    {"ecosystem": "pypi", "match": "django", "label": "Django", "category": "web-framework"},
    {"ecosystem": "pypi", "match": "djangorestframework", "label": "Django REST Framework", "category": "rest-framework"},
    {"ecosystem": "pypi", "match": "fastapi", "label": "FastAPI", "category": "rest-framework"},
    {"ecosystem": "pypi", "match": "sqlalchemy", "label": "SQLAlchemy ORM", "category": "orm"},
    {"ecosystem": "pypi", "match": "celery", "label": "Celery task queue", "category": "message-queue"},
    {"ecosystem": "pypi", "match": "pyjwt", "label": "PyJWT", "category": "security"},

    # --- Go -------------------------------------------------------
    {"ecosystem": "go", "match": "github.com/gin-gonic/gin", "label": "Gin", "category": "rest-framework"},
    {"ecosystem": "go", "match": "github.com/labstack/echo*", "label": "Echo", "category": "rest-framework"},
    {"ecosystem": "go", "match": "github.com/gofiber/fiber*", "label": "Fiber", "category": "rest-framework"},
    {"ecosystem": "go", "match": "gorm.io/gorm", "label": "GORM", "category": "orm"},

    # --- Ruby -------------------------------------------------------
    {"ecosystem": "rubygems", "match": "rails", "label": "Ruby on Rails", "category": "web-framework"},
    {"ecosystem": "rubygems", "match": "sinatra", "label": "Sinatra", "category": "rest-framework"},
    {"ecosystem": "rubygems", "match": "activerecord", "label": "ActiveRecord ORM", "category": "orm"},

    # --- PHP -------------------------------------------------------
    {"ecosystem": "packagist", "match": "laravel/framework", "label": "Laravel", "category": "web-framework"},
    {"ecosystem": "packagist", "match": "symfony/*", "label": "Symfony", "category": "web-framework"},

    # --- .NET -------------------------------------------------------
    {"ecosystem": "nuget", "match": "microsoft.aspnetcore*", "label": "ASP.NET Core", "category": "web-framework"},
    {"ecosystem": "nuget", "match": "entityframework*", "label": "Entity Framework", "category": "orm"},

    # --- Rust -------------------------------------------------------
    {"ecosystem": "cratesio", "match": "actix-web", "label": "Actix Web", "category": "rest-framework"},
    {"ecosystem": "cratesio", "match": "rocket", "label": "Rocket", "category": "rest-framework"},
    {"ecosystem": "cratesio", "match": "diesel", "label": "Diesel ORM", "category": "orm"},
]


def match_dependency(ecosystem: str, name: str) -> Optional[Signature]:
    """First matching signature for one dependency, case-insensitive."""
    name_l = name.lower()
    for sig in SIGNATURES:
        if sig["ecosystem"] == ecosystem and fnmatch.fnmatch(name_l, sig["match"].lower()):
            return sig
    return None


def match_all(dependencies: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Splits a Dependency list into (recognized, unrecognized).

    `recognized` entries carry the original dependency fields plus `label`/
    `category` from the matched signature. `unrecognized` entries pass
    through unchanged so nothing is silently dropped — table coverage gaps
    stay visible and debuggable instead of collapsing to "0 counts."
    """
    recognized: List[Dict[str, Any]] = []
    unrecognized: List[Dict[str, Any]] = []
    for dep in dependencies:
        sig = match_dependency(dep["ecosystem"], dep["name"])
        if sig:
            recognized.append({**dep, "label": sig["label"], "category": sig["category"]})
        else:
            unrecognized.append(dep)
    return recognized, unrecognized

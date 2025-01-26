# Rapport SLH Labo 3
> Auteur : **Edwin HÄFFNER**

## Questions

> 1. Voyez-vous des problèmes avec la politique spécifiée dans l’énoncé ?

Oui, plusieurs problèmes peuvent être identifiés dans la politique spécifiée :

- **Accès illimité des administrateurs :** Donner tous les droits aux administrateurs, y compris l'accès aux données personnelles et médicales des utilisateurs, pose des problèmes de confidentialité et de sécurité... Même les administrateurs ne devraient pas avoir un accès non restreint aux informations sensibles ! En cas de compromission du compte administrateur, toutes les données des utilisateurs seraient exposées, ce qui joue vraiment pas, aie. 

- **Suppression du dossier personnel par l'utilisateur :** Permettre aux utilisateurs de supprimer leur propre dossier médical peut entraîner une perte irréversible de données importantes, ce sont tout de même des informations médicales... Je ne m'y connais pas trop en droit, mais je pense que pouvoir supprimer son dossier médical est une mauvaise idée !

- **Changement de rôle des médecins :** La politique ne précise pas ce qui se passe lorsqu'un médecin change de rôle, je pense que rendre plus clair ce qui se passe lorsqu'un médecin change de rôle serait une bonne idée.

> 2. Parmi les politiques définies ci-dessus, la ou lesquelles serai(en)t pénibles à implémenter s’il
   fallait utiliser à la place d’ABAC un modèle RBAC traditionnel ?

Dans un modèle RBAC (Role-Based Access Control) traditionnel, les permissions sont attribuées à des rôles, et les utilisateurs se voient attribuer ces rôles. Les décisions d'autorisation sont basées sur l'appartenance à un rôle, sans prendre en compte les attributs spécifiques des utilisateurs ou des ressources. Les politiques qui nécessitent des vérifications basées sur les attributs dynamiques des utilisateurs ou des objets seraient donc difficiles à implémenter.
Par exemple, la politique suivante : 

- Un utilisateur peut voir, créer ou détruire son dossier personnel serait compliqué à implémenter, car cette politique dépend de l'id de son dossier `(r.obj.id == r.sub.id)`

Mais cette difficulté est présente sur toutes les politiques qui utilisent des dépendances sur les attributs des utilisateurs... Donc c'est quasiment toutes les politiques de l'énoncé. La seule qui serait facile à implémenter serait la première, qui donne tous les droits aux administrateurs.


>3. Que pensez-vous de l’utilisation d’un Option<UserID> mutable dans la structure Service pour
   garder trace de l’utilisateur loggué ? Comment pourrait-on changer le design pour savoir à la
   compilation si un utilisateur est censé être connecté ou pas ? Est-ce que cela permet d’éliminer
   une partie du traitement d’erreurs ?

Ce design nécessite de vérifier explicitement à chaque opération si un utilisateur est connecté, ce qui peut être source d'erreurs si cette vérification est oubliée. Cela ajoute également du code répétitif et rend le système moins sûr, car un oubli est toujours possible, les programmeurs sont humains après tout.

Pour améliorer ce système et savoir dès la compilation si un utilisateur est connecté ou non, on pourrait utiliser un pattern de typage plus fort en définissant deux structures distinctes :

- Une pour le service non authentifié :
  ```rust
  struct Service {
        db: Database,
        enforcer: Enforcer,
  }
  ```

- Une pour le service authentifié :
  ```rust
  struct AuthenticatedService {
        user_id: UserID,
        db: Database,
        enforcer: Enforcer,
  }
  ```

Les méthodes nécessitant un utilisateur connecté seraient définies uniquement sur `AuthenticatedService`. Donc au final, le compilateur vérifiera que ces méthodes ne peuvent pas être appelées sans authentification préalable, éliminant le risque d'erreurs liées à une vérification manquante de l'état de connexion.


>4. Que pensez-vous de l’utilisation de la macro de dérivation automatique pour Deserialize pour
   les types de model ? Et pour les types de input_validation ?

**Model**
Je ne vois aucun problème avec l'utilisation de la macro de dérivation pour les types de `model`, elle permet d'automatiser la génération de code, réduire le code boiler-plate et d'empêcher d'eventuelles erreurs humaines. Surtout que dans notre cas les types sont plutôt simple donc... aucun problème !

**Input_validation**
Pour les types de `input_validation`, c'est un peu plus compliqué. Les types de `input_validation` sont des types qui sont utilisés pour valider les entrées de l'utilisateur. On veut peut-être effectuer certain traitement sur les données, par exemple effectuer des conversions ou bien valider les données. Donc il est mieux de sérialiser manuellement les données pour avoir un meilleur contrôle sur celles-ci.

>5. Que pensez-vous de l’impact de l’utilisation de Casbin sur la performance de l’application ? sur
   l’efficacité du système de types ?

**Impact sur la performance**
Casbin évalue des politiques d'autorisation **à l'exécution**, donc l'évaluation des règles (surtout si elles sont complexes ou nombreuses) peut introduire de la latence dans le traitement des requêtes, car chaque action nécessite une vérification des permissions.

Après selon l'overview de la doc de casbin, ils disent eux même que leur librairie est plutôt rapide, donc je pense que l'impact sur la performance est plutôt faible, mais il est présent.

Après, je ne pense pas que cet impact soit dramatique dans cette application ou la vitesse n'est pas vraiment de mise. 

**Efficacité du système de types**

L'utilisation de Casbin externalise une partie de la logique d'autorisation en dehors du système de types de Rust. Les politiques sont définies dans des fichiers de configuration (comme `policy.csv`) et évaluées à l'exécution, ce qui signifie que le compilateur ne peut pas vérifier statiquement la conformité aux politiques d'accès, donc c'est pas très efficace, surtout lorsqu'on code. Il est dommage de perdre l'un des avantages de Rust qui est la vérification statique des erreurs.

 En effet, les erreurs liées aux autorisations ne seront détectées qu'à l'exécution, donc cela nous force à tester plus en profondeur notre application pour s'assurer que les autorisations sont correctement gérées. Et même là, on ne peut pas être sûr à 100% que tout est correct.


>6. Avez-vous d’autres remarques ?

Non pas vraiment !
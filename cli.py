from attck_repo import AttckRepository, Technique
from textwrap import indent

def display_technique(t: Technique) -> None:
    print(f"\n{t.technique_id}  {t.name}")
    print(f"Tactique : {t.tactic}")
    print("\nDescription :")
    print(indent(t.description, "  "))
    print("\nOWASP lié :")
    for o in t.appsec_mapping.owasp:
        print(f"  - {o}")
    print("\nExemples de vulnérabilités :")
    for v in t.appsec_mapping.vuln_examples:
        print(f"  - {v}")
    print("\nSignaux de logs possibles :")
    for s in t.appsec_mapping.log_signals:
        print(f"  - {s}")
    print()

def main() -> None:
    repo = AttckRepository("data/attck_appsec.json")

    while True:
        print("\nMenu ATT&CK AppSec")
        print("1. Lister les tactiques")
        print("2. Lister les techniques par tactique")
        print("3. Rechercher une technique")
        print("4. Afficher une technique par ID")
        print("0. Quitter")
        choice = input("Choix : ").strip()

        if choice == "0":
            break

        if choice == "1":
            tactics = repo.list_tactics()
            print("\nTactiques disponibles :")
            for t in tactics:
                print(f"  - {t}")

        elif choice == "2":
            tactic = input("Nom de la tactique : ").strip()
            techniques = repo.get_by_tactic(tactic)
            if not techniques:
                print("Aucune technique trouvée.")
                continue
            for t in techniques:
                print(f"{t.technique_id}  {t.name}")

        elif choice == "3":
            keyword = input("Mot clé (ID, nom, description) : ").strip()
            results = repo.search(keyword)
            if not results:
                print("Aucun résultat.")
                continue
            for t in results:
                print(f"{t.technique_id}  {t.name}  [{t.tactic}]")

        elif choice == "4":
            tid = input("ID de la technique (ex: T1190) : ").strip()
            t = repo.get(tid)
            if not t:
                print("Technique introuvable.")
                continue
            display_technique(t)

        else:
            print("Choix invalide.")

if __name__ == "__main__":
    main()

from bnvd.client import BNVDClient
from bnvd.exceptions import BNVDAPIError, BNVDConnectionError, BNVDInvalidResponse

def main():
    client = BNVDClient()

    try:
        print("🔎 Vulnerabilidades recentes:")
        recentes = client.get_recent(days=2, per_page=3)
        for vul in recentes:
            print(f"{vul['cve_id']} - {vul.get('title', 'Sem título')}")

        print("\n📊 Estatísticas:")
        stats = client.get_stats()
        print(stats)

        print("\n📁 Vulnerabilidades críticas:")
        criticas = client.get_by_severity("CRITICAL")
        print(f"Total críticas: {len(criticas)}")

    except (BNVDAPIError, BNVDConnectionError, BNVDInvalidResponse) as e:
        print(f"Erro ao acessar API: {e}")
    except Exception as e:
        print(f"Erro inesperado: {e}")

if __name__ == "__main__":
    main()

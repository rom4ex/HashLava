from cassandra.cluster import Cluster

cluster = Cluster(['10.16.16.22'])
session = cluster.connect('hashes')

keyspace_name = 'hashes'
tables_query = f"SELECT table_name FROM system_schema.tables WHERE keyspace_name = '{keyspace_name}'"

tables = session.execute(tables_query)
for table in tables:
    table_name = table.table_name
    truncate_query = f"TRUNCATE {keyspace_name}.{table_name};"
    session.execute(truncate_query)

cluster.shutdown()

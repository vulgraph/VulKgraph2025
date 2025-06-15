import os
from urllib.parse import quote
from neo4j import GraphDatabase
from datetime import datetime
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))

with driver.session() as session:
    
    # 获取指定目录中的所有JSON文件
    directory = "/home/deeplearning/nas-files/tplite/document/test_examples"
    directory_url = f"file://{quote(directory)}"
    for filename in os.listdir(directory):
        if filename.endswith(".json"):

            tx = session.begin_transaction()

            filepath = os.path.join(directory, filename)

            # 建立节点bugs(单个节点->查找方式可以为name)
            query1 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "MERGE (b:Bug {name: data.cve.CVE_data_meta.ID}) "
                "SET b.type = data.cve.data_type "
                "SET b.problem_type = data.cve.problemtype.problemtype_data[0].description[0].value "
                "SET b.description = data.cve.description.description_data[0].value "
                "SET b.cvssV2_severity = data.impact.baseMetricV2.severity "
                "SET b.cvssV2_exploitabilityScore = data.impact.baseMetricV2.exploitabilityScore "
                "SET b.cvssV2_impactScore = data.impact.baseMetricV2.impactScore "
                "SET b.cvssV2_baseScore = data.impact.baseMetricV2.cvssV2.baseScore "
                "SET b.cvssV2_vectorString = data.impact.baseMetricV2.cvssV2.vectorString "
                "SET b.operator = data.configurations.nodes[0].operator "
                "SET b.lastModifiedDate =  LEFT(data.lastModifiedDate, 10) "
                "SET b.publishedDate = LEFT(data.publishedDate, 10) "
                "RETURN b"
            )
            result = tx.run(query1)
            for record in result:
                print(record)

            # 建立节点ref
            query2 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MERGE (ref:Reference {name:ref_data.url}) "
                "SET ref.refsource = ref_data.refsource "
            )
            result2 = tx.run(query2)

            # ref节点打上属性tags->对于有值的而言
            query3 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (X:Reference) "
                "WHERE X.name = ref_data.url AND SIZE(ref_data.tags) <> 0 "
                "SET X.tags = ref_data.tags "
                "RETURN X "
            )
            result3 = tx.run(query3)

            # ref节点打上属性tags->对于空的NULL的而言
            query4 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (X:Reference) "
                "WHERE X.name = ref_data.url AND SIZE(ref_data.tags) = 0 "
                "SET X.tags = '[Normal]' "
                "RETURN X "
            )
            result4 = tx.run(query4)

            # 交换了位置改成包含关系了
            query22 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (ref:Reference) "
                "WHERE 'Patch' IN ref.tags "
                "SET ref:Patch "
                "RETURN ref "
            )
            result22 = tx.run(query22)

            # cpe的导入->影响的library
            query5 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.configurations.nodes[0].cpe_match AS node "
                "MERGE (c:Library {name : split(node.cpe23Uri, \":\")[4]+split(node.cpe23Uri, \":\")[5]}) "
                "SET c.Vulnerable = node.vulnerable, "
                "    c.Component_Type = split(node.cpe23Uri, \":\")[2], "
                "    c.Component_Supplier = split(node.cpe23Uri, \":\")[3], "
                "    c.Component_Name = split(node.cpe23Uri, \":\")[4] "
            )
            result5 = tx.run(query5)
            
            # 第一个关系patch<->bugs
            query6 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "MATCH (ref:Reference) "
                "WHERE 'Patch' IN ref.tags AND ref.name = ref_data.url "
                "MERGE (ref)-[r1:useToPatch]->(b)"
            )
            result6 = tx.run(query6)

            query61 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "MATCH (ref:Reference) "
                "WHERE 'Patch' IN ref.tags AND ref.name = ref_data.url "
                "MERGE (b)-[r16:PatchBy]->(ref) "
            )
            result61 = tx.run(query61)
            
            # 第二个关系Bug->Library
            query7 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data AS ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "UNWIND data.configurations.nodes[0].cpe_match AS node "
                "MATCH (c:Library {name: split(node.cpe23Uri, \":\")[4]+ split(node.cpe23Uri, \":\")[5]}) "
                "MERGE (b)-[r2:Affect]->(c) "
            )
            result7 = tx.run(query7)
            
            # 第三个关系ref->bug bug的很大一部分来源->normal
            query8 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "MATCH (ref:Reference {name: ref_data.url})"
                "WHERE ref.tags = '[Normal]' "
                "MERGE (ref)-[r3:Announce]->(b)"
            )
            result8 = tx.run(query8)

            # 第四个关系bugs->Exploit攻击者会利用这个漏洞的某些特性实现攻击
            query9 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "MATCH (ref:Reference {name: ref_data.url}) "
                "WHERE 'Exploit' IN ref.tags "
                "MERGE (b)-[r4:HasExploitBy]->(ref) "
            )
            result9 = tx.run(query9)

            # 第五个关系Vendor->bugs厂商发布的
            query10 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "MATCH (ref:Reference {name: ref_data.url}) "
                "WHERE 'Vendor Advisory' IN ref.tags "
                "MERGE (ref)-[r5:VendorReleased]->(b) "
            )
            result10 = tx.run(query10)

            # 第六个关系BrokenLink->bugs
            query11 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "MATCH (ref:Reference {name: ref_data.url})"
                "WHERE 'Broken Link' IN ref.tags "
                "MERGE (b)-[r6:WillBrokenLink]->(ref)"
            )
            result11 = tx.run(query11)

            # 第七个关系bugs->一些机构(政府/第三方数据库)，可以在后面添加上
            query12 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "MATCH (ref:Reference {name: ref_data.url}) "
                "WHERE 'US Government Resource' IN ref.tags OR 'Third Party Advisory' IN ref.tags "
                "MERGE (b)-[r7:GivenInformationBy]->(ref) "
            )
            result12 = tx.run(query12)

            # 第八个关系 bug->need Permissions Required
            query13 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "MATCH (ref:Reference {name: ref_data.url}) "
                "WHERE 'Permissions Required' IN ref.tags "
                "MERGE (b)-[r8:Need_PermissionsRequired]->(ref)"
            )
            result13 = tx.run(query13)

            # 第九个关系 b->Issue Tracking
            query14 = (
                f"CALL apoc.load.json(\"{directory_url}/{quote(filename)}\") YIELD value AS data "
                "UNWIND data.cve.references.reference_data as ref_data "
                "MATCH (b:Bug{name: data.cve.CVE_data_meta.ID}) "
                "MATCH (ref:Reference {name: ref_data.url}) "
                "WHERE 'Issue Tracking' IN ref.tags "
                "MERGE (b)-[r9:Issue_Tracking_By]->(ref) "
            )
            result14 = tx.run(query14)

            # 第一个归类关系 相同cve关系的汇总
            query15 = (
                "MATCH (b:Bug) "
                "WHERE b.problem_type IS NOT NULL "
                "WITH DISTINCT b.problem_type AS problem_type "
                "MERGE (c:PROBLEM_TYPE {name: problem_type}) "
                "WITH problem_type,c "
                "MATCH (b:Bug {problem_type: problem_type}) "
                "MERGE (b)-[:HAS_PROBLEM_TYPE]->(c) "
            )
            result15 = tx.run(query15)

            # 提交事务
            tx.commit()

def calculate_date_difference(tx, node_label):
    result = tx.run(f"MATCH (n:{node_label}) RETURN id(n) AS id, n.publishedDate AS publishedDate, n.lastModifiedDate AS lastModifiedDate")
    date_format = "%Y-%m-%d"
    for record in result:
        publishedDate = datetime.strptime(record['publishedDate'], date_format)
        lastModifiedDate = datetime.strptime(record['lastModifiedDate'], date_format)
        delta = lastModifiedDate - publishedDate
        # Update the node with the new LASTING property
        tx.run("MATCH (n) WHERE id(n) = $id SET n.LASTING = $lasting", id=record['id'], lasting=delta.days)

with driver.session() as session:
    session.write_transaction(calculate_date_difference, "Bug")

driver.close()

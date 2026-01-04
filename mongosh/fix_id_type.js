// --- CONFIGURATION ---
// List collections here that you DO NOT want to migrate (system logs, etc)
var EXCLUDE = ["system.profile", "system.views", "local.startup_log"]; 
// ---------------------

print("Starting Full Migration...");

var collections = db.getCollectionNames().filter(function(name) {
    return !EXCLUDE.includes(name) && !name.startsWith("system.");
});

// Helper to guess fields that might be references (containing "Id" in the name)
function getReferenceFields(doc) {
    var refs = [];
    Object.keys(doc).forEach(function(key) {
        if (key !== "_id" && key.match(/Id$/i)) { // Matches 'blogId', 'userId', etc.
            refs.push(key);
        }
    });
    return refs;
}

// Step 1: Identify dependencies (Which collection points to which?)
var graph = {}; // { 'comments': [ 'blogs', 'users' ] }
var refTargets = new Set();

collections.forEach(function(colName) {
    var doc = db[colName].findOne();
    if (doc) {
        var refs = getReferenceFields(doc);
        if (refs.length > 0) {
            refs.forEach(function(refField) {
                // Assuming field name matches collection name loosely (e.g., userId -> users)
                // This is a heuristic. Adjust if your naming is different.
                var targetCol = refField.replace(/Id$/, "").toLowerCase() + "s"; // user -> users
                if (targetCol === "categorys") targetCol = "categories"; // Simple pluralization fix
                
                if (collections.includes(targetCol)) {
                    if (!graph[colName]) graph[colName] = [];
                    if (!graph[colName].includes(targetCol)) {
                        graph[colName].push(targetCol);
                        refTargets.add(targetCol);
                    }
                }
            });
        }
    }
});

// Step 2: Determine order
// 1. Collections that are NOT referenced by anything (Roots)
// 2. Collections that reference Roots (Children)
var level1 = collections.filter(function(c) { return !refTargets.has(c); });
var level2 = collections.filter(function(c) { return refTargets.has(c); });

print("\n--- Plan ---");
print("Level 1 (Reference Targets / Parents): " + level1.join(", "));
print("Level 2 (Referencing / Children): " + level2.join(", "));
print("-------------\n");

// Helper to migrate a single collection
function migrateCollection(colName, isParent) {
    var tempName = colName + "_new";
    db[tempName].drop();
    
    var count = 0;
    db[colName].find().forEach(function(doc) {
        var newDoc = Object.assign({}, doc);
        
        // 1. Convert _id
        if (typeof doc._id === 'string') {
            newDoc._id = ObjectId(doc._id);
        }

        // 2. Convert Date fields
        ["createdAt", "updatedAt", "publishedAt", "date", "dob"].forEach(function(dateField) {
            if (newDoc[dateField] && typeof newDoc[dateField] === 'string') {
                newDoc[dateField] = new Date(newDoc[dateField]);
            }
        });

        // 3. If this is a Child, update References to match Parents
        if (!isParent) {
             var refs = getReferenceFields(doc);
             refs.forEach(function(refField) {
                 // We only update if the referenced collection was already migrated (Level 1)
                 // Logic: If the field is a string, it's an old reference. Convert to ObjectId.
                 if (typeof newDoc[refField] === 'string') {
                     newDoc[refField] = ObjectId(newDoc[refField]);
                 }
             });
        }

        db[tempName].insertOne(newDoc);
        count++;
    });
    
    // Swap
    if (count > 0) {
        db[colName].renameCollection(colName + "_old");
        db[tempName].renameCollection(colName);
        print("Migrated: " + colName + " (" + count + " docs)");
    } else {
        print("Skipped (Empty): " + colName);
    }
}

// Step 3: Execute
print("Processing Level 1 (Parents)...");
level1.forEach(function(c) { migrateCollection(c, true); });

print("\nProcessing Level 2 (Children)...");
level2.forEach(function(c) { migrateCollection(c, false); });

print("\n!!! DONE !!!");
print("Check your app. If happy, drop _old collections manually.");

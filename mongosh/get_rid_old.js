db.getCollectionNames().forEach(function(col) {
    if (col.endsWith("_old")) db[col].drop();
});
db.getCollectionNames();

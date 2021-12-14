def initial_trust_score(posture_indices, postures):
    initial = 0.5
    change = trust_calc(posture_indices, postures)
    trust_score = initial + change
    
    if trust_score < 0 :
        trust_score = 0
    if trust_score > 1 :
        trust_score = 1

def trust_calc(changed_postures_indices, changed_postures):
    change = 0
    if 0 in changed_postures_indices:
        change += f1(changed_postures[0])
    
    if 1 in changed_postures_indices:
        change +=f2(changed_postures[1])

    if 2 in changed_postures_indices:
        change += f3(changed_postures[2])
    
    if 3 in changed_postures_indices:
        change +=f1(changed_postures[3])

    if 4 in changed_postures_indices:
        change += f2(changed_postures[4])
    
    if 5 in changed_postures_indices:
        change +=f3(changed_postures[5])
    
    if 6 in changed_postures_indices:
        change +=f1(changed_postures[6])
    
    if 7 in changed_postures_indices:
        change += f2(changed_postures[7])

    return change

def trust_score_change(old_params, new_params, old_score):
    
    changed_postures_indices = []
    changed_postures = []
    
    for i in range(len(old_params)):
        if old_params[i] != new_params[i]:
            changed_postures_indices.append(i)
            changed_postures.append(i)
    

    change = trust_calc(changed_postures_indices, changed_postures)

    trust_score = old_score + change
    if trust_score < 0 :
        trust_score = 0
    if trust_score > 1 :
        trust_score = 1
    
    return trust_score

